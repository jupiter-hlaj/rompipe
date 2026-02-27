#!/usr/bin/env python3
"""
rompipe dashboard — real-time web monitor for the NES-to-SNES pipeline.

Usage: python3 dashboard.py <input.nes> [options]

Opens a browser at http://localhost:5555 showing live pipeline progress,
LLM streaming output, tile conversion counts, and build results.
"""
import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify

# ---------------------------------------------------------------------------
# Pipeline stage definitions (mirrored from main.py)
# ---------------------------------------------------------------------------
STAGES = [
    ("parse_rom",        "parse_rom.py",        "ROM parsing",              True),
    ("disassemble",      "disassemble.py",       "Ghidra disassembly",       False),
    ("translate_cpu",    "translate_cpu.py",     "6502 \u2192 65816 translation", False),
    ("translate_ppu",    "translate_ppu.py",     "PPU wrapper generation",   False),
    ("translate_mapper", "translate_mapper.py",  "Mapper stubs",             False),
    ("convert_graphics", "convert_graphics.py",  "Graphics conversion",      False),
    ("convert_audio",    "convert_audio.py",     "Audio conversion",         False),
    ("build_snes_rom",   "build_snes_rom.py",    "SNES ROM assembly",        True),
]

ANSI_RE = re.compile(r'\033\[[0-9;]*m')
LLM_TOKEN_RE = re.compile(r'\033\[90m(.*?)\033\[0m')

# ---------------------------------------------------------------------------
# Shared pipeline state (thread-safe)
# ---------------------------------------------------------------------------
class PipelineState:
    def __init__(self):
        self.lock = threading.Lock()
        self.rom_manifest: dict = {}
        self.stages: dict = {}
        self.current_stage: str | None = None
        self.llm_tokens: list[str] = []
        self.tile_progress: dict = {}
        self.build_report: dict = {}
        self.log_lines: list[str] = []
        self.pipeline_status: str = "idle"   # idle | running | complete | failed
        self.started_at: float | None = None
        self.sse_queues: list[queue.Queue] = []

    def broadcast(self, event_type: str, data: dict):
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        dead = []
        for q in self.sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            self.sse_queues.remove(q)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "pipeline_status": self.pipeline_status,
                "rom_manifest": self.rom_manifest,
                "current_stage": self.current_stage,
                "stages": self.stages,
                "tile_progress": self.tile_progress,
                "build_report": self.build_report,
                "log_lines": self.log_lines[-500:],
                "llm_tokens": self.llm_tokens[-2000:],
                "elapsed": round(time.time() - self.started_at, 1) if self.started_at else 0,
            }


state = PipelineState()
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Pipeline orchestrator (runs in background thread)
# ---------------------------------------------------------------------------
def build_stage_args(rom_path: Path, args) -> dict:
    workspace_args = ["--workspace", str(args.workspace)]
    return {
        "parse_rom":         [str(rom_path)] + workspace_args,
        "disassemble":       workspace_args,
        "translate_cpu":     workspace_args + (["--no-llm"] if args.no_llm else []) +
                             ["--model", args.claude_model if args.backend != "ollama" else "qwen2.5-coder:14b"] +
                             ["--backend", args.backend],
        "translate_ppu":     workspace_args,
        "translate_mapper":  workspace_args,
        "convert_graphics":  workspace_args + (["--upscale"] if args.upscale else []),
        "convert_audio":     workspace_args + (["--no-llm"] if args.no_llm else []),
        "build_snes_rom":    workspace_args + ["--output", str(args.output)],
    }


def run_stage_captured(stage_id: str, script: str, extra_args: list[str]) -> dict:
    """Run a pipeline stage via Popen, capturing stdout line-by-line."""
    script_path = Path(__file__).parent / script
    cmd = [sys.executable, str(script_path)] + extra_args

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    start = time.time()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env,
    )

    # For translate_cpu: byte-level reading to capture LLM tokens without newline
    if stage_id == "translate_cpu":
        _read_streaming(proc, stage_id, start)
    else:
        _read_lines(proc, stage_id, start)

    proc.wait()
    elapsed = round(time.time() - start, 2)
    success = proc.returncode == 0

    status = "success" if success else "failed"
    with state.lock:
        state.stages[stage_id]["status"] = status
        state.stages[stage_id]["elapsed"] = elapsed
    state.broadcast("stage_end", {"stage": stage_id, "status": status, "elapsed": elapsed})

    return {"stage": stage_id, "success": success,
            "returncode": proc.returncode, "elapsed_seconds": elapsed}


def _read_lines(proc, stage_id: str, start: float):
    """Read stdout line-by-line (all stages except translate_cpu)."""
    for raw in iter(proc.stdout.readline, b''):
        line = raw.decode("utf-8", errors="replace")
        clean = ANSI_RE.sub('', line).rstrip()
        if not clean:
            continue
        elapsed = round(time.time() - start, 1)
        with state.lock:
            state.stages[stage_id]["lines"].append(clean)
            state.log_lines.append(clean)
        state.broadcast("log_line", {"stage": stage_id, "line": clean, "elapsed": elapsed})

        # Parse tile progress
        tile_match = re.search(r'(\d+)/(\d+) tiles converted', clean)
        if tile_match:
            current, total = int(tile_match.group(1)), int(tile_match.group(2))
            with state.lock:
                state.tile_progress = {"current": current, "total": total}
            state.broadcast("tile_progress", {"current": current, "total": total})


def _read_streaming(proc, stage_id: str, start: float):
    """Read stdout with byte-level granularity for LLM token capture."""
    buffer = ""
    fd = proc.stdout.fileno()
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        text = chunk.decode("utf-8", errors="replace")
        buffer += text

        # Extract LLM tokens from ANSI grey sequences
        while "\033[90m" in buffer and "\033[0m" in buffer:
            s = buffer.index("\033[90m")
            e = buffer.index("\033[0m", s)
            token = buffer[s + 5 : e]
            with state.lock:
                state.llm_tokens.append(token)
            state.broadcast("llm_token", {"token": token})
            buffer = buffer[:s] + buffer[e + 4:]

        # Extract complete lines
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            clean = ANSI_RE.sub('', line).strip()
            if clean:
                elapsed = round(time.time() - start, 1)
                with state.lock:
                    state.stages[stage_id]["lines"].append(clean)
                    state.log_lines.append(clean)
                state.broadcast("log_line", {"stage": stage_id, "line": clean, "elapsed": elapsed})


def run_pipeline(rom_path: Path, args):
    """Pipeline orchestrator — runs all stages sequentially."""
    workspace = Path(args.workspace)
    output_dir = Path(args.output)
    workspace.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    state.pipeline_status = "running"
    state.started_at = time.time()
    state.broadcast("pipeline_start", {"rom": str(rom_path)})

    stage_arg_map = build_stage_args(rom_path, args)
    workspace_args = ["--workspace", str(workspace)]
    stage_results = []
    manifest = {}

    for stage_id, script, description, fatal in STAGES:
        if args.skip_audio and stage_id == "convert_audio":
            with state.lock:
                state.stages[stage_id] = {"status": "skipped", "elapsed": 0, "lines": []}
            state.broadcast("stage_skip", {"stage": stage_id})
            stage_results.append({"stage": stage_id, "success": True,
                                   "returncode": 0, "elapsed_seconds": 0.0})
            continue

        with state.lock:
            state.current_stage = stage_id
            state.stages[stage_id] = {"status": "running", "elapsed": 0, "lines": []}
        state.broadcast("stage_start", {"stage": stage_id, "description": description})

        # Clear LLM tokens for new translate_cpu run
        if stage_id == "translate_cpu":
            with state.lock:
                state.llm_tokens.clear()

        result = run_stage_captured(stage_id, script,
                                     stage_arg_map.get(stage_id, workspace_args))
        stage_results.append(result)

        # Load manifest after parse_rom
        if stage_id == "parse_rom":
            manifest_path = workspace / "rom_manifest.json"
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text())
                with state.lock:
                    state.rom_manifest = manifest
                state.broadcast("rom_info", manifest)

        # Load tile map after convert_graphics
        if stage_id == "convert_graphics":
            tile_map_path = workspace / "tile_map.json"
            if tile_map_path.exists():
                try:
                    tiles = json.loads(tile_map_path.read_text())
                    count = len(tiles) if isinstance(tiles, list) else 0
                    with state.lock:
                        state.tile_progress = {"current": count, "total": count}
                    state.broadcast("tile_progress", {"current": count, "total": count})
                except json.JSONDecodeError:
                    pass

        if not result["success"] and fatal:
            state.pipeline_status = "failed"
            state.broadcast("pipeline_failed", {"stage": stage_id})
            # Still write build report
            _write_report(output_dir, rom_path, manifest, stage_results, None)
            _archive_run(rom_path, workspace, output_dir)
            return

    # Load final build report
    sfc_path = output_dir / "output.sfc"
    if not sfc_path.exists():
        sfc_path = None
    report_path = _write_report(output_dir, rom_path, manifest, stage_results, sfc_path)
    if report_path and report_path.exists():
        with state.lock:
            state.build_report = json.loads(report_path.read_text())

    # Archive run before declaring complete
    _archive_run(rom_path, workspace, output_dir)

    state.pipeline_status = "complete"
    state.current_stage = None
    state.broadcast("pipeline_complete", state.build_report)


def _archive_run(rom_path: Path, workspace: Path, output_dir: Path):
    """Copy workspace + output to runs/{rom}_{timestamp}/ for safekeeping."""
    runs_dir = Path(__file__).parent / "runs"
    rom_name = Path(rom_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = runs_dir / f"{rom_name}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    if workspace.exists():
        shutil.copytree(workspace, run_dir / "workspace", dirs_exist_ok=True)
    if output_dir.exists():
        shutil.copytree(output_dir, run_dir / "output", dirs_exist_ok=True)

    msg = f"[rompipe] Run archived: {run_dir}"
    print(msg, flush=True)
    with state.lock:
        state.log_lines.append(msg)
    state.broadcast("log_line", {"stage": "archive", "line": msg, "elapsed": 0})


def _estimate_fidelity(stage_results: list[dict], manifest: dict) -> str:
    if not manifest.get("mapper_supported", False):
        return "UNSUPPORTED_MAPPER"
    failed = [s["stage"] for s in stage_results if not s["success"]]
    if "build_snes_rom" in failed:
        return "BUILD_FAILED"
    if "translate_cpu" in failed:
        return "TRANSLATION_FAILED"
    if {"disassemble", "convert_graphics"} & set(failed):
        return "DEGRADED"
    if failed:
        return "PARTIAL"
    return "HIGH"


def _write_report(output_dir, rom_path, manifest, stage_results, sfc_path):
    report = {
        "input_rom": str(rom_path),
        "mapper": {
            "id": manifest.get("mapper_id"),
            "name": manifest.get("mapper_name"),
            "supported": manifest.get("mapper_supported", False),
        },
        "output_rom": str(sfc_path) if sfc_path else None,
        "stages": stage_results,
        "warnings": [
            f"Stage '{s['stage']}' failed" for s in stage_results if not s["success"]
        ],
        "fidelity_estimate": _estimate_fidelity(stage_results, manifest),
        "total_elapsed_seconds": round(sum(s["elapsed_seconds"] for s in stage_results), 2),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "build_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    return report_path


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return HTML_TEMPLATE


@app.route("/api/state")
def api_state():
    return jsonify(state.snapshot())


@app.route("/api/events")
def sse_stream():
    q = queue.Queue(maxsize=2000)
    state.sse_queues.append(q)

    def generate():
        yield f"event: init\ndata: {json.dumps({'status': state.pipeline_status})}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            if q in state.sse_queues:
                state.sse_queues.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Embedded HTML/CSS/JS
# ---------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rompipe</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --bg: #07070d;
    --card: rgba(255,255,255,0.028);
    --card-hover: rgba(255,255,255,0.045);
    --border: rgba(255,255,255,0.06);
    --border-b: rgba(255,255,255,0.12);
    --t1: #e4e4e7;
    --t2: #a1a1aa;
    --t3: #52525b;
    --blue: #3b82f6;
    --blue-g: rgba(59,130,246,0.15);
    --green: #22c55e;
    --green-g: rgba(34,197,94,0.12);
    --red: #ef4444;
    --red-g: rgba(239,68,68,0.12);
    --amber: #f59e0b;
    --purple: #8b5cf6;
    --ui: -apple-system, BlinkMacSystemFont, 'SF Pro Display', system-ui, sans-serif;
    --mono: 'SF Mono', Menlo, Monaco, 'Cascadia Code', monospace;
    --r: 12px;
    --rs: 8px;
}

body {
    font-family: var(--ui); background: var(--bg); color: var(--t1);
    min-height: 100vh; overflow-x: hidden;
}
body::before {
    content: ''; position: fixed; inset: 0; z-index: -1;
    background:
        radial-gradient(ellipse 600px 400px at 15% 10%, rgba(59,130,246,0.06), transparent),
        radial-gradient(ellipse 500px 500px at 85% 30%, rgba(139,92,246,0.04), transparent),
        radial-gradient(ellipse 400px 300px at 50% 80%, rgba(34,197,94,0.03), transparent);
}

.wrap { max-width: 1200px; margin: 0 auto; padding: 24px 20px; }

/* Header */
header {
    display: flex; align-items: center; gap: 16px;
    margin-bottom: 28px; padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
}
header h1 {
    font-size: 22px; font-weight: 600; letter-spacing: -0.02em;
    background: linear-gradient(135deg, #e4e4e7, #a1a1aa);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
}
.badge {
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.08em; padding: 4px 10px; border-radius: 100px; border: 1px solid;
}
.badge.idle    { color: var(--t3); border-color: var(--t3); }
.badge.running { color: var(--blue); border-color: var(--blue);
                 box-shadow: 0 0 12px var(--blue-g); animation: pulse 2s ease-in-out infinite; }
.badge.complete { color: var(--green); border-color: var(--green);
                  box-shadow: 0 0 12px var(--green-g); }
.badge.failed  { color: var(--red); border-color: var(--red);
                 box-shadow: 0 0 12px var(--red-g); }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.6} }

.elapsed { font-size: 13px; font-family: var(--mono); color: var(--t3); }

/* Card */
.card {
    background: var(--card); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--border); border-radius: var(--r); padding: 20px; margin-bottom: 16px;
    transition: border-color 0.3s;
}
.card:hover { border-color: var(--border-b); }
.card-t {
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.08em; color: var(--t3); margin-bottom: 14px;
}

/* ROM Info */
.rom-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.rom-grid .lab { font-size: 11px; color: var(--t3); margin-bottom: 2px; }
.rom-grid .val { font-size: 15px; font-weight: 500; font-family: var(--mono); }

/* Progress Track */
.track { display: flex; gap: 3px; height: 6px; border-radius: 100px; overflow: hidden;
         background: rgba(255,255,255,0.04); margin-bottom: 20px; }
.seg { flex: 1; border-radius: 100px; transition: background 0.4s ease; }
.seg.pending  { background: rgba(255,255,255,0.06); }
.seg.running  { background: var(--blue); animation: segpulse 1.5s ease-in-out infinite; }
.seg.success  { background: var(--green); }
.seg.failed   { background: var(--red); }
.seg.skipped  { background: rgba(255,255,255,0.08); }
@keyframes segpulse { 0%,100%{opacity:1} 50%{opacity:.5} }

/* Stage List */
.stages { display: flex; flex-direction: column; gap: 2px; }
.srow {
    display: grid; grid-template-columns: 28px 1fr 200px 80px;
    align-items: center; gap: 12px; padding: 10px 12px; border-radius: var(--rs);
    transition: background 0.2s;
}
.srow:hover { background: var(--card-hover); }
.srow.active { background: rgba(59,130,246,0.06); border: 1px solid rgba(59,130,246,0.12); }
.dot { width: 10px; height: 10px; border-radius: 50%; transition: all 0.3s; }
.dot.pending  { background: var(--t3); opacity: .4; }
.dot.running  { background: var(--blue); box-shadow: 0 0 8px var(--blue-g);
                animation: dotpulse 1.5s ease-in-out infinite; }
.dot.success  { background: var(--green); }
.dot.failed   { background: var(--red); box-shadow: 0 0 8px var(--red-g); }
.dot.skipped  { background: var(--t3); opacity: .2; }
@keyframes dotpulse { 0%,100%{transform:scale(1);box-shadow:0 0 8px var(--blue-g)}
                      50%{transform:scale(1.3);box-shadow:0 0 16px rgba(59,130,246,.3)} }
.sname { font-size: 13px; font-weight: 500; }
.sdesc { font-size: 12px; color: var(--t2); }
.stime { font-size: 12px; font-family: var(--mono); color: var(--t3); text-align: right; }

/* LLM Output */
.llm {
    background: rgba(0,0,0,0.35); border: 1px solid var(--border); border-radius: var(--rs);
    padding: 16px; font-family: var(--mono); font-size: 12px; line-height: 1.6;
    color: var(--t3); max-height: 280px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
}
.llm .tk { color: #6ee7b7; }
.cursor {
    display: inline-block; width: 7px; height: 14px; background: var(--blue);
    border-radius: 1px; animation: blink .8s step-end infinite; vertical-align: text-bottom;
}
@keyframes blink { 50%{opacity:0} }

/* Log Viewer */
.log {
    background: rgba(0,0,0,0.35); border: 1px solid var(--border); border-radius: var(--rs);
    padding: 12px; font-family: var(--mono); font-size: 11px; line-height: 1.7;
    color: var(--t2); max-height: 300px; overflow-y: auto;
}
.log .pf { color: var(--blue); }

/* Grid */
.g2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 768px) { .g2 { grid-template-columns: 1fr; } }

/* Fidelity */
.fid {
    display: inline-block; font-size: 13px; font-weight: 700; font-family: var(--mono);
    padding: 6px 14px; border-radius: var(--rs); letter-spacing: 0.04em;
}
.fid.HIGH            { background: var(--green-g); color: var(--green); border: 1px solid rgba(34,197,94,.2); }
.fid.PARTIAL         { background: rgba(245,158,11,.1); color: var(--amber); border: 1px solid rgba(245,158,11,.2); }
.fid.DEGRADED        { background: var(--red-g); color: var(--red); border: 1px solid rgba(239,68,68,.2); }
.fid.BUILD_FAILED    { background: var(--red-g); color: var(--red); border: 1px solid rgba(239,68,68,.2); }
.fid.TRANSLATION_FAILED { background: var(--red-g); color: var(--red); border: 1px solid rgba(239,68,68,.2); }
.fid.UNSUPPORTED_MAPPER { background: rgba(139,92,246,.1); color: var(--purple); border: 1px solid rgba(139,92,246,.2); }

/* Tile bar */
.tile-bar-track { height: 6px; background: rgba(255,255,255,0.06); border-radius: 100px; margin-top: 10px; }
.tile-bar-fill  { height: 100%; background: var(--green); border-radius: 100px; transition: width 0.3s; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,.08); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.15); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>rompipe</h1>
    <span class="badge idle" id="badge">IDLE</span>
    <span style="flex:1"></span>
    <span class="elapsed" id="elapsed">--</span>
  </header>

  <div class="card" id="rom-card" style="display:none">
    <div class="card-t">ROM Information</div>
    <div class="rom-grid" id="rom-info"></div>
  </div>

  <div class="track" id="track"></div>

  <div class="card">
    <div class="card-t">Pipeline Stages</div>
    <div class="stages" id="stages"></div>
  </div>

  <div class="card" id="llm-card" style="display:none">
    <div class="card-t">LLM Translation Output</div>
    <div class="llm" id="llm"><span class="cursor"></span></div>
  </div>

  <div class="g2">
    <div class="card" id="tiles-card" style="display:none">
      <div class="card-t">Tile Conversion</div>
      <div id="tile-stats"></div>
    </div>
    <div class="card" id="result-card" style="display:none">
      <div class="card-t">Build Result</div>
      <div id="result"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-t">Pipeline Log</div>
    <div class="log" id="log"></div>
  </div>
</div>

<script>
const ST=[
  {id:"parse_rom",       name:"parse_rom",       desc:"ROM parsing"},
  {id:"disassemble",     name:"disassemble",      desc:"Ghidra disassembly"},
  {id:"translate_cpu",   name:"translate_cpu",    desc:"6502 \u2192 65816 translation"},
  {id:"translate_ppu",   name:"translate_ppu",    desc:"PPU wrapper generation"},
  {id:"translate_mapper",name:"translate_mapper",  desc:"Mapper stubs"},
  {id:"convert_graphics",name:"convert_graphics", desc:"Graphics conversion"},
  {id:"convert_audio",   name:"convert_audio",    desc:"Audio conversion"},
  {id:"build_snes_rom",  name:"build_snes_rom",   desc:"SNES ROM assembly"},
];

// Build UI
const track=document.getElementById('track');
const stages=document.getElementById('stages');
ST.forEach(s=>{
  const seg=document.createElement('div');
  seg.className='seg pending'; seg.id='seg-'+s.id;
  track.appendChild(seg);

  const row=document.createElement('div');
  row.className='srow'; row.id='row-'+s.id;
  row.innerHTML=`
    <div class="dot pending" id="dot-${s.id}"></div>
    <div><div class="sname">${s.name}</div><div class="sdesc">${s.desc}</div></div>
    <div class="sdesc" id="det-${s.id}"></div>
    <div class="stime" id="tm-${s.id}">--</div>`;
  stages.appendChild(row);
});

let startTime=null;
let pipelineDone=false;
function setBadge(s){
  const b=document.getElementById('badge');
  b.className='badge '+s; b.textContent=s.toUpperCase();
}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}

// SSE
const es=new EventSource('/api/events');

es.addEventListener('init',e=>{
  const d=JSON.parse(e.data); setBadge(d.status);
});

es.addEventListener('pipeline_start',e=>{
  setBadge('running'); startTime=Date.now();
});

es.addEventListener('stage_start',e=>{
  const d=JSON.parse(e.data);
  setBadge('running');
  if(!startTime) startTime=Date.now();
  const dot=document.getElementById('dot-'+d.stage);
  const seg=document.getElementById('seg-'+d.stage);
  const row=document.getElementById('row-'+d.stage);
  if(dot) dot.className='dot running';
  if(seg) seg.className='seg running';
  if(row) row.classList.add('active');
  if(d.stage==='translate_cpu'){
    document.getElementById('llm-card').style.display='';
    document.getElementById('llm').innerHTML='<span class="cursor"></span>';
  }
});

es.addEventListener('stage_end',e=>{
  const d=JSON.parse(e.data);
  const cls=d.status==='success'?'success':'failed';
  const dot=document.getElementById('dot-'+d.stage);
  const seg=document.getElementById('seg-'+d.stage);
  const row=document.getElementById('row-'+d.stage);
  const tm=document.getElementById('tm-'+d.stage);
  if(dot) dot.className='dot '+cls;
  if(seg) seg.className='seg '+cls;
  if(row) row.classList.remove('active');
  if(tm) tm.textContent=d.elapsed.toFixed(1)+'s';
});

es.addEventListener('stage_skip',e=>{
  const d=JSON.parse(e.data);
  const dot=document.getElementById('dot-'+d.stage);
  const seg=document.getElementById('seg-'+d.stage);
  const tm=document.getElementById('tm-'+d.stage);
  if(dot) dot.className='dot skipped';
  if(seg) seg.className='seg skipped';
  if(tm) tm.textContent='skip';
});

es.addEventListener('rom_info',e=>{
  const m=JSON.parse(e.data);
  document.getElementById('rom-card').style.display='';
  const fn=m.source_rom?m.source_rom.split('/').pop():'--';
  const prg=m.prg_rom_size_bytes?(m.prg_rom_size_bytes/1024)+'KB':'--';
  const chr=m.chr_ram?'CHR-RAM':(m.chr_rom_size_bytes?(m.chr_rom_size_bytes/1024)+'KB':'--');
  document.getElementById('rom-info').innerHTML=`
    <div><div class="lab">ROM</div><div class="val">${esc(fn)}</div></div>
    <div><div class="lab">Mapper</div><div class="val">${esc(m.mapper_name||'--')}</div></div>
    <div><div class="lab">PRG-ROM</div><div class="val">${prg}</div></div>
    <div><div class="lab">CHR</div><div class="val">${chr}</div></div>
    <div><div class="lab">Mirroring</div><div class="val">${esc(m.mirroring||'--')}</div></div>
    <div><div class="lab">Format</div><div class="val">${esc(m.format||'iNES')}</div></div>`;
});

es.addEventListener('llm_token',e=>{
  const d=JSON.parse(e.data);
  const box=document.getElementById('llm');
  const cur=box.querySelector('.cursor');
  const sp=document.createElement('span');
  sp.className='tk'; sp.textContent=d.token;
  box.insertBefore(sp,cur);
  box.scrollTop=box.scrollHeight;
});

es.addEventListener('log_line',e=>{
  const d=JSON.parse(e.data);
  const log=document.getElementById('log');
  const el=document.createElement('div');
  el.className='log-line';
  const m=d.line.match(/^(\[[\w_]+\])(.*)/);
  if(m) el.innerHTML='<span class="pf">'+esc(m[1])+'</span>'+esc(m[2]);
  else el.textContent=d.line;
  log.appendChild(el);
  log.scrollTop=log.scrollHeight;
});

es.addEventListener('tile_progress',e=>{
  const d=JSON.parse(e.data);
  document.getElementById('tiles-card').style.display='';
  const pct=d.total>0?Math.round(d.current/d.total*100):0;
  document.getElementById('tile-stats').innerHTML=`
    <div style="font-size:28px;font-weight:700;font-family:var(--mono)">${d.current}<span style="font-size:14px;color:var(--t3)"> / ${d.total}</span></div>
    <div style="font-size:12px;color:var(--t3);margin-top:2px">tiles converted (${pct}%)</div>
    <div class="tile-bar-track"><div class="tile-bar-fill" style="width:${pct}%"></div></div>`;
});

es.addEventListener('pipeline_complete',e=>{
  const d=JSON.parse(e.data);
  pipelineDone=true;
  setBadge('complete');
  document.getElementById('result-card').style.display='';
  const f=d.fidelity_estimate||'UNKNOWN';
  const out=d.output_rom?d.output_rom.split('/').pop():'--';
  document.getElementById('result').innerHTML=`
    <div class="fid ${f}">${f}</div>
    <div style="margin-top:12px;font-size:13px;color:var(--t2)">
      Total: <span style="font-family:var(--mono)">${d.total_elapsed_seconds||'--'}s</span><br>
      Output: <span style="font-family:var(--mono)">${esc(out)}</span>
    </div>
    ${(d.warnings||[]).length?'<div style="margin-top:8px;font-size:12px;color:var(--amber)">'+d.warnings.map(w=>'&#x26A0; '+esc(w)).join('<br>')+'</div>':''}`;
});

es.addEventListener('pipeline_failed',e=>{
  pipelineDone=true;
  setBadge('failed');
});

// Elapsed timer
setInterval(()=>{
  if(startTime && !pipelineDone){
    document.getElementById('elapsed').textContent=((Date.now()-startTime)/1000).toFixed(1)+'s';
  }
},100);

// Reconnect / refresh: load accumulated state
fetch('/api/state').then(r=>r.json()).then(d=>{
  setBadge(d.pipeline_status);
  if(d.started_at || d.pipeline_status!=='idle') startTime=startTime||Date.now();

  // ROM info
  if(d.rom_manifest && d.rom_manifest.mapper_name){
    const evt=new CustomEvent('x');
    es.dispatchEvent(Object.assign(new MessageEvent('rom_info',{data:JSON.stringify(d.rom_manifest)})));
  }

  // Replay stages
  Object.entries(d.stages||{}).forEach(([id,info])=>{
    const dot=document.getElementById('dot-'+id);
    const seg=document.getElementById('seg-'+id);
    const row=document.getElementById('row-'+id);
    const tm=document.getElementById('tm-'+id);
    if(!dot) return;
    if(info.status==='running'){
      dot.className='dot running'; seg.className='seg running'; row.classList.add('active');
    } else if(info.status==='success'||info.status==='failed'){
      dot.className='dot '+info.status; seg.className='seg '+info.status;
      if(tm) tm.textContent=info.elapsed.toFixed(1)+'s';
    } else if(info.status==='skipped'){
      dot.className='dot skipped'; seg.className='seg skipped';
      if(tm) tm.textContent='skip';
    }
  });

  // Replay log
  const log=document.getElementById('log');
  (d.log_lines||[]).forEach(line=>{
    const el=document.createElement('div'); el.className='log-line';
    const m=line.match(/^(\[[\w_]+\])(.*)/);
    if(m) el.innerHTML='<span class="pf">'+esc(m[1])+'</span>'+esc(m[2]);
    else el.textContent=line;
    log.appendChild(el);
  });
  log.scrollTop=log.scrollHeight;

  // Replay LLM tokens
  if(d.llm_tokens && d.llm_tokens.length){
    document.getElementById('llm-card').style.display='';
    const box=document.getElementById('llm');
    const cur=box.querySelector('.cursor');
    d.llm_tokens.forEach(t=>{
      const sp=document.createElement('span');
      sp.className='tk'; sp.textContent=t;
      box.insertBefore(sp,cur);
    });
    box.scrollTop=box.scrollHeight;
  }

  // Tile progress
  if(d.tile_progress && d.tile_progress.total){
    const tp=d.tile_progress;
    document.getElementById('tiles-card').style.display='';
    const pct=tp.total>0?Math.round(tp.current/tp.total*100):0;
    document.getElementById('tile-stats').innerHTML=`
      <div style="font-size:28px;font-weight:700;font-family:var(--mono)">${tp.current}<span style="font-size:14px;color:var(--t3)"> / ${tp.total}</span></div>
      <div style="font-size:12px;color:var(--t3);margin-top:2px">tiles converted (${pct}%)</div>
      <div class="tile-bar-track"><div class="tile-bar-fill" style="width:${pct}%"></div></div>`;
  }

  // Build result
  if(d.build_report && d.build_report.fidelity_estimate){
    document.getElementById('result-card').style.display='';
    const br=d.build_report;
    const f=br.fidelity_estimate;
    const out=br.output_rom?br.output_rom.split('/').pop():'--';
    document.getElementById('result').innerHTML=`
      <div class="fid ${f}">${f}</div>
      <div style="margin-top:12px;font-size:13px;color:var(--t2)">
        Total: <span style="font-family:var(--mono)">${br.total_elapsed_seconds||'--'}s</span><br>
        Output: <span style="font-family:var(--mono)">${esc(out)}</span>
      </div>`;
  }
});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="rompipe dashboard \u2014 real-time NES\u2192SNES pipeline monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("rom", help="Input .nes ROM file")
    parser.add_argument("--workspace",     default="workspace")
    parser.add_argument("--output",        default="output")
    parser.add_argument("--upscale",       action="store_true")
    parser.add_argument("--skip-audio",    action="store_true")
    parser.add_argument("--no-llm",        action="store_true")
    parser.add_argument("--backend",       default="anthropic", choices=["anthropic", "ollama"])
    parser.add_argument("--claude-model",  default="claude-sonnet-4-6")
    parser.add_argument("--mapper-override", type=int, default=None)
    parser.add_argument("--port",          type=int, default=5555)
    parser.add_argument("--no-browser",    action="store_true",
                        help="Don't auto-open browser")
    args = parser.parse_args()

    rom_path = Path(args.rom)
    if not rom_path.exists():
        print(f"ERROR: ROM not found: {rom_path}", file=sys.stderr)
        sys.exit(1)

    # Start pipeline in background thread after Flask binds
    def delayed_start():
        time.sleep(1.5)
        run_pipeline(rom_path, args)

    pipeline_thread = threading.Thread(target=delayed_start, daemon=True)
    pipeline_thread.start()

    # Auto-open browser
    if not args.no_browser:
        def open_browser():
            time.sleep(2)
            webbrowser.open(f"http://localhost:{args.port}")
        threading.Thread(target=open_browser, daemon=True).start()

    print(f"\n  rompipe dashboard: http://localhost:{args.port}\n", flush=True)
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True,
            use_reloader=False)


if __name__ == "__main__":
    main()
