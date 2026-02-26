#!/usr/bin/env python3
"""
Stage 2: disassemble.py
Disassembles NES PRG-ROM using Ghidra headless (primary) or capstone (fallback).
Outputs per-bank .asm files, function boundaries, call graph, and hardware register
access sites used by translate_cpu.py and translate_ppu.py.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# NES hardware register map — any access to these addresses is flagged
NES_PPU_REGS = {
    0x2000: "PPUCTRL",   0x2001: "PPUMASK",   0x2002: "PPUSTATUS",
    0x2003: "OAMADDR",   0x2004: "OAMDATA",   0x2005: "PPUSCROLL",
    0x2006: "PPUADDR",   0x2007: "PPUDATA",   0x4014: "OAMDMA",
}
NES_APU_REGS = {
    0x4000: "SQ1_VOL",   0x4001: "SQ1_SWEEP", 0x4002: "SQ1_LO",   0x4003: "SQ1_HI",
    0x4004: "SQ2_VOL",   0x4005: "SQ2_SWEEP", 0x4006: "SQ2_LO",   0x4007: "SQ2_HI",
    0x4008: "TRI_LINEAR",0x400A: "TRI_LO",    0x400B: "TRI_HI",
    0x400C: "NOISE_VOL", 0x400E: "NOISE_LO",  0x400F: "NOISE_HI",
    0x4010: "DMC_FREQ",  0x4011: "DMC_RAW",   0x4012: "DMC_START", 0x4013: "DMC_LEN",
    0x4015: "APU_STATUS",0x4017: "FRAME_CNT",
}
ALL_HW_REGS = {**NES_PPU_REGS, **NES_APU_REGS}


def find_ghidra() -> Path | None:
    """Locate Ghidra installation (Homebrew cask or manual /Applications placement)."""
    candidates = [
        Path("/Applications/ghidra"),
        Path("/opt/homebrew/Caskroom/ghidra"),
    ]
    # Check Homebrew cask install path
    try:
        result = subprocess.run(
            ["brew", "--prefix", "ghidra"], capture_output=True, text=True
        )
        if result.returncode == 0:
            candidates.insert(0, Path(result.stdout.strip()))
    except FileNotFoundError:
        pass

    # Look for versioned Ghidra dirs
    for base in candidates:
        if base.exists():
            # Homebrew cask nests under version
            for child in sorted(base.iterdir(), reverse=True):
                analyze = child / "support" / "analyzeHeadless"
                if analyze.exists():
                    return analyze
            analyze = base / "support" / "analyzeHeadless"
            if analyze.exists():
                return analyze
    return None


def disassemble_with_ghidra(
    prg_bin: Path, manifest: dict, workspace: Path, scripts_dir: Path
) -> bool:
    """Run Ghidra headless analysis. Returns True on success."""
    ghidra = find_ghidra()
    if not ghidra:
        print("[disassemble] Ghidra not found — using capstone fallback", file=sys.stderr)
        return False

    java_script = scripts_dir / "NESAnalyzer.java"
    if not java_script.exists():
        print("[disassemble] NESAnalyzer.java not found in scripts/ — using capstone fallback",
              file=sys.stderr)
        return False

    disasm_dir = workspace / "disasm"
    disasm_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)
        vectors = manifest.get("interrupt_vectors", {})
        reset_addr = vectors.get("RESET", "0xFFFC").replace("0x", "")
        nmi_addr   = vectors.get("NMI",   "0xFFFA").replace("0x", "")
        irq_addr   = vectors.get("IRQ",   "0xFFFE").replace("0x", "")

        env = os.environ.copy()
        env["NES_RESET"] = reset_addr
        env["NES_NMI"]   = nmi_addr
        env["NES_IRQ"]   = irq_addr
        env["NES_DISASM_OUT"] = str(disasm_dir)

        cmd = [
            str(ghidra),
            str(project_dir),
            "NESProject",
            "-import", str(prg_bin),
            "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x8000",
            "-postScript", str(java_script),
            "-scriptPath", str(scripts_dir),
            "-deleteProject",
            "-noanalysis",
        ]

        print(f"[disassemble] Running Ghidra headless...")
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"[disassemble] Ghidra failed (rc={result.returncode}), falling back to capstone",
                  file=sys.stderr)
            print(result.stderr[-2000:], file=sys.stderr)
            return False

    print("[disassemble] Ghidra analysis complete")
    return True


def disassemble_with_capstone(prg_bin: Path, manifest: dict, workspace: Path):
    """Fallback: recursive-descent disassembly using capstone."""
    try:
        import capstone
    except ImportError:
        print("[disassemble] ERROR: capstone not installed. Run: pip3 install capstone",
              file=sys.stderr)
        sys.exit(1)

    prg_data = prg_bin.read_bytes()
    disasm_dir = workspace / "disasm"
    disasm_dir.mkdir(parents=True, exist_ok=True)

    md = capstone.Cs(capstone.CS_ARCH_6502, capstone.CS_MODE_6502)
    md.detail = True

    vectors = manifest.get("interrupt_vectors", {})
    base = 0x8000
    prg_size = len(prg_data)

    # Collect all entry points
    entry_addrs = set()
    for vec_name, vec_str in vectors.items():
        try:
            addr = int(vec_str, 16)
            entry_addrs.add(addr)
        except ValueError:
            pass

    visited = set()
    functions = {}
    register_accesses = []

    def disassemble_from(start_addr: int) -> list:
        instructions = []
        queue = [start_addr]
        seen = set()
        while queue:
            addr = queue.pop()
            if addr in seen or addr < base or addr >= base + prg_size:
                continue
            seen.add(addr)
            offset = addr - base
            chunk = prg_data[offset: offset + 64]
            for insn in md.disasm(chunk, addr):
                if insn.address in seen:
                    break
                seen.add(insn.address)
                instructions.append(insn)
                # Track hardware register accesses
                for op in insn.operands if hasattr(insn, 'operands') else []:
                    pass
                # Simple operand check from mnemonic text
                mnem = insn.mnemonic.upper()
                op_str = insn.op_str
                for hw_addr, hw_name in ALL_HW_REGS.items():
                    if f"${hw_addr:04x}" in op_str.lower() or f"${hw_addr:04X}" in op_str:
                        access_type = "write" if mnem in ("STA", "STX", "STY", "STZ") else "read"
                        register_accesses.append({
                            "address": f"0x{insn.address:04X}",
                            "hw_address": f"0x{hw_addr:04X}",
                            "hw_name": hw_name,
                            "type": "PPU" if hw_addr in NES_PPU_REGS else "APU",
                            "access": access_type,
                            "mnemonic": mnem,
                        })
                # Follow control flow
                if mnem == "JSR":
                    try:
                        target = int(op_str.replace("$", ""), 16)
                        queue.append(target)
                    except ValueError:
                        pass
                if mnem in ("JMP", "BRK", "RTI", "RTS"):
                    if mnem == "JMP" and not op_str.startswith("("):
                        try:
                            target = int(op_str.replace("$", ""), 16)
                            queue.append(target)
                        except ValueError:
                            pass
                    break
                # Handle branches
                if mnem in ("BEQ", "BNE", "BCC", "BCS", "BMI", "BPL", "BVC", "BVS"):
                    try:
                        target = int(op_str.replace("$", ""), 16)
                        queue.append(target)
                    except ValueError:
                        pass
        return instructions

    all_instructions = {}
    for entry in sorted(entry_addrs):
        insns = disassemble_from(entry)
        for insn in insns:
            all_instructions[insn.address] = insn

    # Group into "banks" of 16KB each
    bank_size = 0x4000
    num_banks = max(1, prg_size // bank_size)
    for bank_idx in range(num_banks):
        bank_base = base + bank_idx * bank_size
        bank_end  = bank_base + bank_size
        lines = [f"; NES PRG Bank {bank_idx:02d} — ${bank_base:04X}–${bank_end - 1:04X}",
                 f".org ${bank_base:04X}", ""]
        for addr in sorted(k for k in all_instructions if bank_base <= k < bank_end):
            insn = all_instructions[addr]
            lines.append(f"${addr:04X}:  {insn.mnemonic:<6} {insn.op_str}")
        (disasm_dir / f"bank_{bank_idx:02d}.asm").write_text("\n".join(lines))

    # Stub functions.json and call_graph.json
    functions_data = {}
    for entry in sorted(entry_addrs):
        name = {v: k for k, v in {
            "NMI": int(vectors.get("NMI", "0"), 16),
            "RESET": int(vectors.get("RESET", "0"), 16),
            "IRQ": int(vectors.get("IRQ", "0"), 16),
        }.items()}.get(entry, f"sub_{entry:04X}")
        functions_data[f"0x{entry:04X}"] = {
            "name": name, "start": f"0x{entry:04X}",
            "callers": [], "callees": [],
        }

    (workspace / "disasm" / "functions.json").write_text(json.dumps(functions_data, indent=2))
    (workspace / "disasm" / "register_accesses.json").write_text(
        json.dumps(register_accesses, indent=2)
    )
    (workspace / "disasm" / "call_graph.json").write_text(json.dumps({}, indent=2))

    print(f"[disassemble] capstone: {len(all_instructions)} instructions across {num_banks} banks")
    print(f"[disassemble] capstone: {len(register_accesses)} hardware register accesses found")


def main():
    parser = argparse.ArgumentParser(description="Disassemble NES PRG-ROM")
    parser.add_argument("--workspace", default="workspace")
    args = parser.parse_args()

    workspace   = Path(args.workspace)
    scripts_dir = Path(__file__).parent / "scripts"
    prg_bin     = workspace / "prg_rom.bin"
    manifest    = json.loads((workspace / "rom_manifest.json").read_text())

    if not prg_bin.exists():
        print("ERROR: prg_rom.bin not found — run parse_rom.py first", file=sys.stderr)
        sys.exit(1)

    print(f"[disassemble] PRG size: {prg_bin.stat().st_size // 1024} KB")

    success = disassemble_with_ghidra(prg_bin, manifest, workspace, scripts_dir)
    if not success:
        print("[disassemble] Using capstone fallback disassembler")
        disassemble_with_capstone(prg_bin, manifest, workspace)

    disasm_dir = workspace / "disasm"
    bank_files = list(disasm_dir.glob("bank_*.asm"))
    print(f"[disassemble] Output: {len(bank_files)} bank file(s) in {disasm_dir}/")


if __name__ == "__main__":
    main()
