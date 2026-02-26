#!/usr/bin/env python3
"""
NES → SNES ROM Port Pipeline Orchestrator
Usage: python3 main.py <input.nes> [options]

Runs all 8 pipeline stages sequentially:
  1. parse_rom       — iNES header decode, PRG/CHR extraction
  2. disassemble     — Ghidra/capstone 6502 disassembly
  3. translate_cpu   — 6502 → 65816 translation (det. + LLM)
  4. translate_ppu   — SNES PPU wrapper generation
  5. translate_mapper— Mapper bank-switch stubs
  6. convert_graphics— CHR 2bpp → SNES 4bpp
  7. convert_audio   — NES APU → SPC700 BRR
  8. build_snes_rom  — ca65/ld65 assemble → .sfc
"""
import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

# Pipeline stage definitions: (stage_id, script, description, fatal_on_fail)
STAGES = [
    ("parse_rom",        "parse_rom.py",        "ROM parsing",              True),
    ("disassemble",      "disassemble.py",       "Ghidra disassembly",       False),
    ("translate_cpu",    "translate_cpu.py",     "6502→65816 translation",   False),
    ("translate_ppu",    "translate_ppu.py",     "PPU wrapper generation",   False),
    ("translate_mapper", "translate_mapper.py",  "Mapper stubs",             False),
    ("convert_graphics", "convert_graphics.py",  "Graphics conversion",      False),
    ("convert_audio",    "convert_audio.py",     "Audio conversion",         False),
    ("build_snes_rom",   "build_snes_rom.py",    "SNES ROM assembly",        True),
]


def setup_logging(output_dir: Path) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "pipeline.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_path),
        ],
    )
    return logging.getLogger("rompipe")


def run_stage(stage_id: str, script: str, extra_args: list[str],
              workspace: Path, log: logging.Logger) -> dict:
    script_path = Path(__file__).parent / script
    cmd = [sys.executable, str(script_path)] + extra_args
    log.info(f"--- Stage: {stage_id} ---")
    log.info(f"Command: {' '.join(str(c) for c in cmd)}")

    start = time.time()
    result = subprocess.run(cmd, capture_output=False, text=True)
    elapsed = round(time.time() - start, 2)

    success = result.returncode == 0
    level = logging.INFO if success else logging.ERROR
    log.log(level, f"Stage '{stage_id}': {'OK' if success else 'FAILED'} in {elapsed}s")

    return {
        "stage": stage_id,
        "success": success,
        "returncode": result.returncode,
        "elapsed_seconds": elapsed,
    }


def estimate_fidelity(stage_results: list[dict], manifest: dict) -> str:
    if not manifest.get("mapper_supported", False):
        return "UNSUPPORTED_MAPPER"
    failed = [s["stage"] for s in stage_results if not s["success"]]
    if "build_snes_rom" in failed:
        return "BUILD_FAILED"
    if "translate_cpu" in failed:
        return "TRANSLATION_FAILED"
    critical_failed = {"disassemble", "convert_graphics"} & set(failed)
    if critical_failed:
        return "DEGRADED"
    if failed:
        return "PARTIAL"
    return "HIGH"


def write_build_report(output_dir: Path, input_rom: Path, manifest: dict,
                       stage_results: list[dict], sfc_path: Path | None):
    report = {
        "input_rom": str(input_rom),
        "mapper": {
            "id": manifest.get("mapper_id"),
            "name": manifest.get("mapper_name"),
            "supported": manifest.get("mapper_supported", False),
        },
        "output_rom": str(sfc_path) if sfc_path else None,
        "stages": stage_results,
        "warnings": [
            f"Stage '{s['stage']}' failed — degraded output" for s in stage_results if not s["success"]
        ],
        "fidelity_estimate": estimate_fidelity(stage_results, manifest),
        "total_elapsed_seconds": round(sum(s["elapsed_seconds"] for s in stage_results), 2),
    }
    report_path = output_dir / "build_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="NES → SNES ROM port pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("rom", help="Input .nes ROM file")
    parser.add_argument("--workspace",     default="workspace",  help="Working directory (default: workspace/)")
    parser.add_argument("--output",        default="output",     help="Output directory (default: output/)")
    parser.add_argument("--upscale",       action="store_true",  help="Upscale CHR tiles via ComfyUI")
    parser.add_argument("--skip-audio",    action="store_true",  help="Skip audio conversion stage")
    parser.add_argument("--no-llm",        action="store_true",  help="Disable LLM translation pass")
    parser.add_argument("--backend",       default="anthropic", choices=["anthropic", "ollama"],
                        help="LLM backend: anthropic or ollama (default: anthropic)")
    parser.add_argument("--claude-model",  default="claude-sonnet-4-6",
                        help="LLM model name (default: claude-sonnet-4-6)")
    parser.add_argument("--mapper-override", type=int, default=None, help="Override mapper detection")
    args = parser.parse_args()

    rom_path    = Path(args.rom)
    workspace   = Path(args.workspace)
    output_dir  = Path(args.output)

    if not rom_path.exists():
        print(f"ERROR: ROM file not found: {rom_path}", file=sys.stderr)
        sys.exit(1)

    log = setup_logging(output_dir)
    log.info(f"=== rompipe: NES → SNES port pipeline ===")
    log.info(f"Input ROM: {rom_path}")
    log.info(f"Workspace: {workspace}")
    log.info(f"Output:    {output_dir}")

    # Build per-stage argument lists
    workspace_args = ["--workspace", str(workspace)]
    stage_args = {
        "parse_rom":         [str(rom_path)] + workspace_args,
        "disassemble":       workspace_args,
        "translate_cpu":     workspace_args + (["--no-llm"] if args.no_llm else []) +
                             ["--model", args.claude_model if args.backend != "ollama" else "qwen3:8b"] +
                             ["--backend", args.backend],
        "translate_ppu":     workspace_args,
        "translate_mapper":  workspace_args,
        "convert_graphics":  workspace_args + (["--upscale"] if args.upscale else []),
        "convert_audio":     workspace_args + (["--no-llm"] if args.no_llm else []),
        "build_snes_rom":    workspace_args + ["--output", str(output_dir)],
    }

    stage_results = []
    manifest = {}

    for stage_id, script, description, fatal in STAGES:
        if args.skip_audio and stage_id == "convert_audio":
            log.info(f"--- Stage: {stage_id} SKIPPED (--skip-audio) ---")
            stage_results.append({"stage": stage_id, "success": True,
                                   "returncode": 0, "elapsed_seconds": 0.0})
            continue

        result = run_stage(stage_id, script, stage_args.get(stage_id, workspace_args),
                           workspace, log)
        stage_results.append(result)

        # Load manifest after parse_rom for use in build report
        if stage_id == "parse_rom":
            manifest_path = workspace / "rom_manifest.json"
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text())

        if not result["success"] and fatal:
            log.error(f"Fatal stage '{stage_id}' failed — aborting pipeline")
            write_build_report(output_dir, rom_path, manifest, stage_results, None)
            sys.exit(1)

    # Locate output ROM
    sfc_path = output_dir / "output.sfc"
    if not sfc_path.exists():
        sfc_path = None

    report_path = write_build_report(output_dir, rom_path, manifest, stage_results, sfc_path)
    report = json.loads(report_path.read_text())

    log.info("=== Pipeline complete ===")
    log.info(f"Fidelity estimate: {report['fidelity_estimate']}")
    log.info(f"Total time:        {report['total_elapsed_seconds']}s")
    log.info(f"Build report:      {report_path}")

    if sfc_path:
        log.info(f"Output ROM:        {sfc_path}")
        print(f"\nOutput: {sfc_path}")
    else:
        log.error("No .sfc output produced")
        sys.exit(1)

    if report["warnings"]:
        print("\nWarnings:")
        for w in report["warnings"]:
            print(f"  • {w}")


if __name__ == "__main__":
    main()
