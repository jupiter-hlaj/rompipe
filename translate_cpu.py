#!/usr/bin/env python3
"""
Stage 3: translate_cpu.py
Two-pass 6502 → 65816 translation.

Pass 1: Deterministic pre-processor — mechanical opcode substitution,
        hardware register access replacement with JSR wrappers,
        65816 init preamble injection at RESET handler.

Pass 2: Claude API — handles hard cases: self-modifying code, computed
        indirect jumps, NMI handler, mapper IRQ handler, cross-bank calls.

Output: workspace/translated/bank_NN_65816.asm, workspace/translation_log.json
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import anthropic
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    anthropic = None

try:
    import requests as _requests
except ImportError:
    _requests = None

# ---------------------------------------------------------------------------
# Hardware register → wrapper function mapping
# Any STA/STX/STY to these addresses becomes a JSR to the wrapper
# ---------------------------------------------------------------------------
HW_WRITE_WRAPPERS = {
    "$2000": "PPU_CTRL_WRITE",
    "$2001": "PPU_MASK_WRITE",
    "$2003": "OAM_ADDR_WRITE",
    "$2004": "OAM_DATA_WRITE",
    "$2005": "PPU_SCROLL_WRITE",
    "$2006": "PPU_ADDR_WRITE",
    "$2007": "PPU_DATA_WRITE",
    "$4014": "OAM_DMA_TRIGGER",
    "$4000": "APU_SQ1_VOL",
    "$4001": "APU_SQ1_SWEEP",
    "$4002": "APU_SQ1_LO",
    "$4003": "APU_SQ1_HI",
    "$4004": "APU_SQ2_VOL",
    "$4005": "APU_SQ2_SWEEP",
    "$4006": "APU_SQ2_LO",
    "$4007": "APU_SQ2_HI",
    "$4008": "APU_TRI_LINEAR",
    "$400a": "APU_TRI_LO",
    "$400b": "APU_TRI_HI",
    "$400c": "APU_NOISE_VOL",
    "$400e": "APU_NOISE_LO",
    "$400f": "APU_NOISE_HI",
    "$4010": "APU_DMC_FREQ",
    "$4011": "APU_DMC_RAW",
    "$4012": "APU_DMC_START",
    "$4013": "APU_DMC_LEN",
    "$4015": "APU_STATUS_WRITE",
    "$4017": "APU_FRAME_CNT",
}
HW_READ_WRAPPERS = {
    "$2002": "PPU_STATUS_READ",
    "$2007": "PPU_DATA_READ",
    "$4015": "APU_STATUS_READ",
    "$4016": "JOYPAD1_READ",
    "$4017": "JOYPAD2_READ",
}

# 6502 instructions that store to memory (writes)
STORE_MNEMONICS = {"STA", "STX", "STY", "STZ"}
# 6502 instructions that load from memory (reads)
LOAD_MNEMONICS  = {"LDA", "LDX", "LDY", "BIT"}

# Patterns that trigger LLM translation
LLM_TRIGGER_PATTERNS = [
    re.compile(r"\bJMP\s+\(", re.IGNORECASE),          # indirect jump
    re.compile(r";\s*self.modif", re.IGNORECASE),       # self-modifying annotation
    re.compile(r"\bJSR\b.*bank", re.IGNORECASE),        # cross-bank JSR annotations
    re.compile(r"\$[89AB][0-9A-Fa-f]{3}:", re.IGNORECASE),  # mapper reg write (label)
]

# Conditional branch mnemonics and their logical inverses
BRANCH_MNEMONICS = {"BCC", "BCS", "BEQ", "BNE", "BPL", "BMI", "BVC", "BVS"}
BRANCH_INVERT = {
    "BCC": "BCS", "BCS": "BCC",
    "BEQ": "BNE", "BNE": "BEQ",
    "BPL": "BMI", "BMI": "BPL",
    "BVC": "BVS", "BVS": "BVC",
}

# 65816 RESET preamble injected before the translated RESET handler body
RESET_PREAMBLE_65816 = """\
    ; === 65816 initialization — injected by translate_cpu.py ===
    SEI                 ; disable interrupts
    CLC
    XCE                 ; switch CPU to 65816 native mode
    REP #$30            ; A/X/Y = 16-bit
    LDX #$01FF
    TXS                 ; set stack pointer
    REP #$20            ; A = 16-bit
    LDA #$0000
    TCD                 ; Direct Page register = $0000 (Zero Page compat)
    SEP #$30            ; back to 8-bit A/X/Y for NES code compatibility
    ; === end 65816 init ===
"""


def normalize_ghidra_line(line: str) -> str:
    """Normalize Ghidra's disassembly format to ca65-compatible syntax.

    - Convert 0x hex prefix to $ prefix: `0xFF` -> `$FF`, `#0x0` -> `#$00`
    - Strip `<UNSUPPORTED>` tags from implied-mode instructions
    """
    # Strip <UNSUPPORTED> (Ghidra emits this for implied-mode operands)
    line = line.replace("<UNSUPPORTED>", "").rstrip()
    # Convert 0xNN hex literals to $NN (handles #0x and plain 0x)
    line = re.sub(r'#0x([0-9A-Fa-f]+)', lambda m: '#$' + m.group(1).upper().zfill(2), line)
    line = re.sub(r'(?<![#\w])0x([0-9A-Fa-f]+)', lambda m: '$' + m.group(1).upper().zfill(2), line)
    return line


def preprocess_line(line: str, reset_vec: int, skip_counter: list) -> tuple[str, bool]:
    """
    Deterministic pre-processor: applies mechanical substitutions to one line.
    Returns (transformed_line, needs_llm).
    skip_counter is a single-element list [int] used to generate unique branch skip labels.
    """
    # Normalize Ghidra output format first
    line = normalize_ghidra_line(line)

    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return line, False

    parts = stripped.split(None, 2)
    if not parts:
        return line, False

    # ---- Label detection ----
    if parts[0].endswith(":"):
        label_name = parts[0].rstrip(":")
        # Inject 65816 init preamble after the RESET handler label
        if label_name in ("RESET", "RESET_HANDLER"):
            return line + "\n" + RESET_PREAMBLE_65816, False
        # Also match by address for disassemblers that emit numeric labels
        try:
            addr = int(label_name.lstrip("$"), 16)
            if addr == reset_vec:
                return line + "\n" + RESET_PREAMBLE_65816, False
        except ValueError:
            pass
        return line, False

    mnem = parts[0].upper()
    op   = parts[1] if len(parts) > 1 else ""
    op_lower = op.lower().split(",")[0].strip()

    needs_llm = False
    indent = line[: len(line) - len(line.lstrip())]

    # ---- Conditional branch expansion → inverted-condition + JMP ----
    # 6502 relative branches have only ±127 byte range. After reassembly into
    # SNES banks the targets are often far away, causing ca65 range errors.
    # Expand every conditional branch to a 3-instruction sequence that has no
    # range restriction: Bcc skip / JMP target / skip:
    if mnem in BRANCH_MNEMONICS:
        target = op.split(";")[0].strip()
        inverted = BRANCH_INVERT[mnem]
        skip_lbl = f"_brl_{skip_counter[0]}"
        skip_counter[0] += 1
        expanded = (
            f"{indent}{inverted} {skip_lbl}    ; was: {mnem} {target}\n"
            f"{indent}JMP {target}\n"
            f"{skip_lbl}:"
        )
        return expanded, False

    # ---- Hardware register write: STA/STX/STY $2000–$401F ----
    if mnem in STORE_MNEMONICS and op_lower in HW_WRITE_WRAPPERS:
        wrapper = HW_WRITE_WRAPPERS[op_lower]
        indent = line[: len(line) - len(line.lstrip())]
        return f"{indent}JSR {wrapper}    ; was: {mnem} {op}", False

    # ---- Hardware register read: LDA/LDX/LDY $2002, $2007 ----
    if mnem in LOAD_MNEMONICS and op_lower in HW_READ_WRAPPERS:
        wrapper = HW_READ_WRAPPERS[op_lower]
        indent = line[: len(line) - len(line.lstrip())]
        return f"{indent}JSR {wrapper}    ; was: {mnem} {op}", False

    # ---- Indirect jump — flag for LLM ----
    if mnem == "JMP" and "(" in op:
        needs_llm = True

    # ---- Zero Page → Direct Page remapping (transparent in 65816 when D=$0000) ----
    # No change needed; 65816 DP instructions use same addressing modes

    # ---- Cross-bank call detection (JSR to different bank) ----
    if mnem == "JSR":
        needs_llm = any(p.search(line) for p in LLM_TRIGGER_PATTERNS)

    return line, needs_llm


def preprocess_bank(asm_text: str, reset_vec: int,
                    skip_counter: list | None = None) -> tuple[str, list[int]]:
    """
    Run Pass 1 on a full bank .asm file.
    Returns (transformed_text, line_numbers_needing_llm).
    skip_counter is an optional single-element list shared across banks so that
    generated branch-skip labels (_brl_N) are unique across the entire assembled ROM.
    """
    if skip_counter is None:
        skip_counter = [0]
    lines = asm_text.splitlines(keepends=True)
    out_lines = []
    llm_lines = []
    for i, line in enumerate(lines):
        transformed, needs_llm = preprocess_line(line, reset_vec, skip_counter)
        out_lines.append(transformed)
        if needs_llm:
            llm_lines.append(i)
    return "".join(out_lines), llm_lines


def extract_functions(functions_json: dict) -> list[dict]:
    """Convert functions.json into a sorted list for batching."""
    funcs = []
    for addr_str, info in functions_json.items():
        funcs.append({
            "addr": int(addr_str, 16),
            "addr_str": addr_str,
            "name": info.get("name", f"sub_{addr_str}"),
            "callers": info.get("callers", []),
            "callees": info.get("callees", []),
        })
    return sorted(funcs, key=lambda f: f["addr"])


def build_llm_system_prompt() -> str:
    return (
        "You are an expert 6502 and 65816 assembly programmer translating NES game code to SNES.\n"
        "Rules:\n"
        "1. Output ONLY valid ca65 assembler syntax for 65816. No explanation, no markdown.\n"
        "2. Preserve all original behavior exactly — this is a faithful port.\n"
        "3. The SNES runs with SEP #$30 set (8-bit A, X, Y) for 6502 compatibility.\n"
        "4. Direct Page register (D) = $0000 so zero-page references remain valid as DP operands.\n"
        "5. Hardware register accesses ($2000–$401F) have been pre-replaced with JSR wrappers — "
        "do NOT re-emit raw hardware stores or loads.\n"
        "6. Annotate uncertain instructions with a comment: ; REVIEW: <reason>\n"
        "7. For cross-bank JSR, use JSL (long call). For cross-bank RTS, use RTL.\n"
        "8. Self-modifying code: move modified data to WRAM ($7E bank). "
        "Replace code patches with indirect calls through WRAM function pointer tables.\n"
        "9. Begin output immediately with the function label — no preamble.\n"
    )


def call_ollama(model: str, system_prompt: str, user_msg: str,
                base_url: str = "http://localhost:11434") -> str:
    """Call Ollama's local API and return the response text."""
    if _requests is None:
        raise RuntimeError("requests package not installed — pip install requests")
    resp = _requests.post(
        f"{base_url}/api/chat",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
            "stream": False,
            "options": {"num_predict": 2048, "temperature": 0.2},
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def validate_asm_snippet(asm_text: str, workspace: Path) -> bool:
    """Quick check: can ca65 parse this snippet without errors?"""
    import subprocess, tempfile
    # Wrap in a minimal valid context
    test_asm = '.setcpu "65816"\n.smart\n' + asm_text
    tmp = workspace / "_validate_tmp.asm"
    tmp_o = workspace / "_validate_tmp.o"
    try:
        tmp.write_text(test_asm)
        result = subprocess.run(
            ["ca65", "--cpu", "65816", "-o", str(tmp_o), str(tmp)],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False
    finally:
        tmp.unlink(missing_ok=True)
        tmp_o.unlink(missing_ok=True)


def call_llm_translate(client, functions_batch: list[dict], rom_name: str,
                       mapper_name: str, model: str,
                       backend: str = "anthropic",
                       workspace: Path = None) -> list[dict]:
    """Send a batch of functions to LLM and return translated results.

    backend: "anthropic" for Claude API, "ollama" for local Ollama.
    """
    results = []
    system_prompt = build_llm_system_prompt()

    for func in functions_batch:
        source = func.get("source_asm", "; (source not available)")
        user_msg = (
            f"ROM: {rom_name}, Mapper: {mapper_name}\n"
            f"Function: {func['name']} at PRG address {func['addr_str']}\n"
            f"Called from: {', '.join(func['callers']) or 'unknown'}\n"
            f"Calls to: {', '.join(func['callees']) or 'none'}\n\n"
            f"6502 source:\n{source}\n\n"
            f"Translate to 65816. Begin with label {func['name']}_65816:"
        )

        review_count = 0
        try:
            if backend == "ollama":
                translated = call_ollama(model, system_prompt, user_msg)
            else:
                message = client.messages.create(
                    model=model,
                    max_tokens=2048,
                    messages=[{"role": "user", "content": user_msg}],
                    system=system_prompt,
                )
                translated = message.content[0].text
            # Strip markdown code fences that local LLMs sometimes emit
            translated = re.sub(r"```\w*\n?", "", translated).strip()
            # Validate the output actually assembles
            if workspace and not validate_asm_snippet(translated, workspace):
                print(f"[translate_cpu]     {func['name']}: LLM output failed ca65 validation — using stub")
                translated = None
            else:
                review_count = translated.count("; REVIEW:")
                confidence = max(0.0, 1.0 - review_count * 0.1)
        except Exception as e:
            translated = None
            confidence = 0.0

        if translated is None:
            stub_label = f"{func['name']}_65816"
            translated = (
                f"{stub_label}:\n"
                f"    BRK\n"
                f"    RTL"
            )
            confidence = 0.0

        # Wrap in .ifndef guard to prevent duplicate definitions across banks
        guard_label = f"{func['name']}_65816"
        translated = f".ifndef {guard_label}\n{translated}\n.endif"

        results.append({
            "addr": func["addr_str"],
            "name": func["name"],
            "translated": translated,
            "confidence": round(confidence, 2),
            "review_count": review_count,
        })

    return results


def translate_banks(workspace: Path, manifest: dict, model: str, use_llm: bool, args=None):
    disasm_dir    = workspace / "disasm"
    translated_dir = workspace / "translated"
    translated_dir.mkdir(parents=True, exist_ok=True)

    reset_vec = int(manifest["interrupt_vectors"]["RESET"], 16)
    nmi_vec   = int(manifest["interrupt_vectors"]["NMI"],   16)
    irq_vec   = int(manifest["interrupt_vectors"]["IRQ"],   16)

    functions_path = disasm_dir / "functions.json"
    functions_data = json.loads(functions_path.read_text()) if functions_path.exists() else {}

    client = None
    backend = getattr(args, "backend", "anthropic") if hasattr(args, "backend") else "anthropic"
    if use_llm:
        if backend == "ollama":
            # Verify Ollama is running
            try:
                if _requests is None:
                    raise RuntimeError("requests package not installed")
                r = _requests.get("http://localhost:11434/api/tags", timeout=5)
                r.raise_for_status()
                print(f"[translate_cpu] Using Ollama backend, model: {model}")
            except Exception as e:
                print(f"[translate_cpu] WARNING: Ollama not reachable ({e}) — skipping LLM pass",
                      file=sys.stderr)
                use_llm = False
        else:
            if anthropic is None:
                print("[translate_cpu] WARNING: anthropic package not installed — skipping LLM pass",
                      file=sys.stderr)
                use_llm = False
            else:
                api_key = os.environ.get("ANTHROPIC_API_KEY")
                if not api_key:
                    print("[translate_cpu] WARNING: ANTHROPIC_API_KEY not set — skipping LLM pass",
                          file=sys.stderr)
                    use_llm = False
                else:
                    client = anthropic.Anthropic(api_key=api_key)

    translation_log = []
    bank_files = sorted(disasm_dir.glob("bank_*.asm"))
    # Shared counter ensures _brl_N skip labels are unique across all bank files
    global_skip_counter = [0]

    for bank_file in bank_files:
        print(f"[translate_cpu] Processing {bank_file.name} ...")
        asm_text = bank_file.read_text()

        # Pass 1: deterministic pre-processing
        transformed, llm_line_nums = preprocess_bank(asm_text, reset_vec, global_skip_counter)

        # Pass 2: LLM for flagged functions (NMI, IRQ, and complex cases)
        if use_llm and (client or backend == "ollama") and functions_data:
            funcs_to_translate = []
            for addr_str, info in functions_data.items():
                addr = int(addr_str, 16)
                # Always send interrupt handlers to LLM; also send flagged functions
                is_interrupt = addr in (nmi_vec, irq_vec)
                if is_interrupt or llm_line_nums:
                    model_choice = model  # use the configured model for all
                    funcs_to_translate.append({
                        **info,
                        "addr_str": addr_str,
                        "source_asm": info.get("source_asm", f"; {info.get('name', addr_str)} - no source"),
                        "_model": model_choice,
                    })

            if funcs_to_translate:
                print(f"[translate_cpu]   LLM pass: {len(funcs_to_translate)} function(s) via {backend}")
                results = call_llm_translate(
                    client, funcs_to_translate,
                    manifest.get("source_rom", "unknown"),
                    manifest.get("mapper_name", "unknown"),
                    model,
                    backend=backend,
                    workspace=workspace,
                )
                translation_log.extend(results)
                # Append LLM translations as comments/overrides at the end of the bank file
                llm_section = "\n; ---- LLM-translated functions ----\n"
                for r in results:
                    llm_section += f"\n{r['translated']}\n"
                    if r["confidence"] < 0.5:
                        llm_section += f"; WARNING: low confidence ({r['confidence']}) — manual review needed\n"
                transformed += llm_section

        out_path = translated_dir / bank_file.name.replace(".asm", "_65816.asm")
        out_path.write_text(transformed)

    # Write translation log
    log_path = workspace / "translation_log.json"
    log_path.write_text(json.dumps(translation_log, indent=2))
    print(f"[translate_cpu] Translation log: {log_path}")
    print(f"[translate_cpu] Output: {len(list(translated_dir.glob('*.asm')))} bank file(s) in {translated_dir}/")


def main():
    parser = argparse.ArgumentParser(description="Translate 6502 ASM to 65816 ASM")
    parser.add_argument("--workspace", default="workspace")
    parser.add_argument("--model", default="claude-sonnet-4-6",
                        help="LLM model name (default: claude-sonnet-4-6)")
    parser.add_argument("--backend", default="anthropic", choices=["anthropic", "ollama"],
                        help="LLM backend: anthropic (Claude API) or ollama (local)")
    parser.add_argument("--no-llm", action="store_true",
                        help="Skip LLM pass (deterministic pre-processing only)")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    manifest_path = workspace / "rom_manifest.json"
    if not manifest_path.exists():
        print("ERROR: rom_manifest.json not found — run parse_rom.py first", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text())
    use_llm = not args.no_llm

    backend = args.backend
    if backend == "ollama" and args.model.startswith("claude"):
        args.model = "qwen2.5-coder:7b"  # default Ollama model for code
    print(f"[translate_cpu] LLM: {'enabled (' + backend + '/' + args.model + ')' if use_llm else 'disabled'}")
    translate_banks(workspace, manifest, args.model, use_llm, args)


if __name__ == "__main__":
    main()
