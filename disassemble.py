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
import time
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
        Path("/opt/homebrew/share"),   # manual extract location
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


def _ghidra_env() -> dict:
    """Build environment with JAVA_HOME set for Homebrew OpenJDK 21 (Ghidra compatible)."""
    env = os.environ.copy()
    # Ghidra 11.x requires Java 21 LTS — NOT Java 25
    jdk_path = Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")
    if jdk_path.exists():
        env["JAVA_HOME"] = str(jdk_path)
        env["PATH"] = f"/opt/homebrew/opt/openjdk@21/bin:{env.get('PATH', '')}"
    return env


def disassemble_with_ghidra(
    prg_bin: Path, manifest: dict, workspace: Path, scripts_dir: Path
) -> bool:
    """Run Ghidra headless analysis per-bank. Returns True on success.

    NES PRG-ROM is split into 16KB banks. Each bank is loaded at the correct
    NES CPU address: switchable banks at $8000, fixed last bank at $C000.
    This ensures Ghidra's analysis and cross-references work correctly.
    """
    ghidra = find_ghidra()
    if not ghidra:
        print("[disassemble] Ghidra not found — using capstone fallback", file=sys.stderr)
        return False

    ghidra_script = scripts_dir / "NESAnalyzer.py"
    if not ghidra_script.exists():
        print("[disassemble] NESAnalyzer.py not found in scripts/ — using capstone fallback",
              file=sys.stderr)
        return False

    disasm_dir = workspace / "disasm"
    disasm_dir.mkdir(parents=True, exist_ok=True)

    prg_data = prg_bin.read_bytes()
    bank_size = 0x4000  # 16KB
    num_banks = len(prg_data) // bank_size
    if num_banks == 0:
        print("[disassemble] PRG too small for Ghidra — using capstone fallback", file=sys.stderr)
        return False

    vectors = manifest.get("interrupt_vectors", {})
    env = _ghidra_env()

    # We analyze the LAST bank (fixed at $C000) with full analysis + vectors,
    # then each switchable bank at $8000 with basic analysis.
    # Merge all results into combined functions.json.
    all_functions = {}
    all_reg_accesses = []

    for bank_idx in range(num_banks):
        bank_offset = bank_idx * bank_size
        bank_data = prg_data[bank_offset:bank_offset + bank_size]
        is_last = (bank_idx == num_banks - 1)
        base_addr = 0xC000 if is_last else 0x8000

        # Write bank chunk to temp file
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            bank_bin = Path(tmpdir) / f"bank_{bank_idx:02d}.bin"
            bank_bin.write_bytes(bank_data)

            bank_env = env.copy()
            bank_env["NES_DISASM_OUT"] = str(disasm_dir)
            bank_env["NES_BANK_IDX"] = str(bank_idx)

            if is_last:
                # Only set vectors for the fixed bank
                bank_env["NES_RESET"] = vectors.get("RESET", "").replace("0x", "")
                bank_env["NES_NMI"]   = vectors.get("NMI",   "").replace("0x", "")
                bank_env["NES_IRQ"]   = vectors.get("IRQ",   "").replace("0x", "")
            else:
                bank_env["NES_RESET"] = ""
                bank_env["NES_NMI"]   = ""
                bank_env["NES_IRQ"]   = ""

            cmd = [
                str(ghidra),
                str(project_dir),
                f"Bank{bank_idx:02d}",
                "-import", str(bank_bin),
                "-processor", "6502:LE:16:default",
                "-loader", "BinaryLoader",
                "-loader-baseAddr", f"0x{base_addr:04X}",
                "-postScript", str(ghidra_script),
                "-scriptPath", str(scripts_dir),
                "-deleteProject",
            ]

            print(f"[disassemble] Ghidra: bank {bank_idx:02d}/{num_banks-1} @ ${base_addr:04X} ... ", end="", flush=True)
            t0 = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, env=bank_env,
                                    timeout=120)
            elapsed = round(time.time() - t0, 1)
            # Extract function/register counts from script output
            script_summary = ""
            for line in result.stdout.split("\n"):
                if "exported" in line:
                    script_summary = line.split("exported")[-1].strip()
            if result.returncode != 0:
                print(f"FAILED ({elapsed}s)", flush=True)
                # Write empty bank file as fallback
                (disasm_dir / f"bank_{bank_idx:02d}.asm").write_text(
                    f"; NES PRG Bank {bank_idx:02d}\n")
                continue
            else:
                if script_summary:
                    print(f"OK ({elapsed}s) — {script_summary}", flush=True)
                else:
                    print(f"OK ({elapsed}s)", flush=True)

        # Merge functions from this bank
        funcs_path = disasm_dir / "functions.json"
        if funcs_path.exists():
            try:
                bank_funcs = json.loads(funcs_path.read_text())
                all_functions.update(bank_funcs)
            except json.JSONDecodeError:
                pass

        regs_path = disasm_dir / "register_accesses.json"
        if regs_path.exists():
            try:
                bank_regs = json.loads(regs_path.read_text())
                if isinstance(bank_regs, list):
                    all_reg_accesses.extend(bank_regs)
            except json.JSONDecodeError:
                pass

    # Write merged results
    (disasm_dir / "functions.json").write_text(json.dumps(all_functions, indent=2))
    (disasm_dir / "register_accesses.json").write_text(json.dumps(all_reg_accesses, indent=2))

    total_funcs = len(all_functions)
    total_instrs = sum(
        len(f.get("source_asm", "").strip().split("\n"))
        for f in all_functions.values()
        if f.get("source_asm")
    )
    print(f"[disassemble] Ghidra: {total_funcs} functions, {total_instrs} instructions across {num_banks} banks")
    return True


def disassemble_with_capstone(prg_bin: Path, manifest: dict, workspace: Path):
    """Fallback: pure-Python recursive-descent 6502 disassembler (no capstone needed)."""
    prg_data = prg_bin.read_bytes()
    disasm_dir = workspace / "disasm"
    disasm_dir.mkdir(parents=True, exist_ok=True)

    # 6502 opcode table: opcode -> (mnemonic, addressing_mode, instruction_length)
    OPCODES = {
        0x00:("BRK","imp",1), 0x01:("ORA","izx",2), 0x05:("ORA","zp",2),  0x06:("ASL","zp",2),
        0x08:("PHP","imp",1), 0x09:("ORA","imm",2), 0x0A:("ASL","acc",1), 0x0D:("ORA","abs",3),
        0x0E:("ASL","abs",3), 0x10:("BPL","rel",2), 0x11:("ORA","izy",2), 0x15:("ORA","zpx",2),
        0x16:("ASL","zpx",2), 0x18:("CLC","imp",1), 0x19:("ORA","aby",3), 0x1D:("ORA","abx",3),
        0x1E:("ASL","abx",3), 0x20:("JSR","abs",3), 0x21:("AND","izx",2), 0x24:("BIT","zp",2),
        0x25:("AND","zp",2),  0x26:("ROL","zp",2),  0x28:("PLP","imp",1), 0x29:("AND","imm",2),
        0x2A:("ROL","acc",1), 0x2C:("BIT","abs",3), 0x2D:("AND","abs",3), 0x2E:("ROL","abs",3),
        0x30:("BMI","rel",2), 0x31:("AND","izy",2), 0x35:("AND","zpx",2), 0x36:("ROL","zpx",2),
        0x38:("SEC","imp",1), 0x39:("AND","aby",3), 0x3D:("AND","abx",3), 0x3E:("ROL","abx",3),
        0x40:("RTI","imp",1), 0x41:("EOR","izx",2), 0x45:("EOR","zp",2),  0x46:("LSR","zp",2),
        0x48:("PHA","imp",1), 0x49:("EOR","imm",2), 0x4A:("LSR","acc",1), 0x4C:("JMP","abs",3),
        0x4D:("EOR","abs",3), 0x4E:("LSR","abs",3), 0x50:("BVC","rel",2), 0x51:("EOR","izy",2),
        0x55:("EOR","zpx",2), 0x56:("LSR","zpx",2), 0x58:("CLI","imp",1), 0x59:("EOR","aby",3),
        0x5D:("EOR","abx",3), 0x5E:("LSR","abx",3), 0x60:("RTS","imp",1), 0x61:("ADC","izx",2),
        0x65:("ADC","zp",2),  0x66:("ROR","zp",2),  0x68:("PLA","imp",1), 0x69:("ADC","imm",2),
        0x6A:("ROR","acc",1), 0x6C:("JMP","ind",3), 0x6D:("ADC","abs",3), 0x6E:("ROR","abs",3),
        0x70:("BVS","rel",2), 0x71:("ADC","izy",2), 0x75:("ADC","zpx",2), 0x76:("ROR","zpx",2),
        0x78:("SEI","imp",1), 0x79:("ADC","aby",3), 0x7D:("ADC","abx",3), 0x7E:("ROR","abx",3),
        0x81:("STA","izx",2), 0x84:("STY","zp",2),  0x85:("STA","zp",2),  0x86:("STX","zp",2),
        0x88:("DEY","imp",1), 0x8A:("TXA","imp",1), 0x8C:("STY","abs",3), 0x8D:("STA","abs",3),
        0x8E:("STX","abs",3), 0x90:("BCC","rel",2), 0x91:("STA","izy",2), 0x94:("STY","zpx",2),
        0x95:("STA","zpx",2), 0x96:("STX","zpy",2), 0x98:("TYA","imp",1), 0x99:("STA","aby",3),
        0x9A:("TXS","imp",1), 0x9D:("STA","abx",3), 0xA0:("LDY","imm",2), 0xA1:("LDA","izx",2),
        0xA2:("LDX","imm",2), 0xA4:("LDY","zp",2),  0xA5:("LDA","zp",2),  0xA6:("LDX","zp",2),
        0xA8:("TAY","imp",1), 0xA9:("LDA","imm",2), 0xAA:("TAX","imp",1), 0xAC:("LDY","abs",3),
        0xAD:("LDA","abs",3), 0xAE:("LDX","abs",3), 0xB0:("BCS","rel",2), 0xB1:("LDA","izy",2),
        0xB4:("LDY","zpx",2), 0xB5:("LDA","zpx",2), 0xB6:("LDX","zpy",2), 0xB8:("CLV","imp",1),
        0xB9:("LDA","aby",3), 0xBA:("TSX","imp",1), 0xBC:("LDY","abx",3), 0xBD:("LDA","abx",3),
        0xBE:("LDX","aby",3), 0xC0:("CPY","imm",2), 0xC1:("CMP","izx",2), 0xC4:("CPY","zp",2),
        0xC5:("CMP","zp",2),  0xC6:("DEC","zp",2),  0xC8:("INY","imp",1), 0xC9:("CMP","imm",2),
        0xCA:("DEX","imp",1), 0xCC:("CPY","abs",3), 0xCD:("CMP","abs",3), 0xCE:("DEC","abs",3),
        0xD0:("BNE","rel",2), 0xD1:("CMP","izy",2), 0xD5:("CMP","zpx",2), 0xD6:("DEC","zpx",2),
        0xD8:("CLD","imp",1), 0xD9:("CMP","aby",3), 0xDD:("CMP","abx",3), 0xDE:("DEC","abx",3),
        0xE0:("CPX","imm",2), 0xE1:("SBC","izx",2), 0xE4:("CPX","zp",2),  0xE5:("SBC","zp",2),
        0xE6:("INC","zp",2),  0xE8:("INX","imp",1), 0xE9:("SBC","imm",2), 0xEA:("NOP","imp",1),
        0xEC:("CPX","abs",3), 0xED:("SBC","abs",3), 0xEE:("INC","abs",3), 0xF0:("BEQ","rel",2),
        0xF1:("SBC","izy",2), 0xF5:("SBC","zpx",2), 0xF6:("INC","zpx",2), 0xF8:("SED","imp",1),
        0xF9:("SBC","aby",3), 0xFD:("SBC","abx",3), 0xFE:("INC","abx",3),
    }
    BRANCHES = {"BPL","BMI","BVC","BVS","BCC","BCS","BNE","BEQ"}
    TERMINATORS = {"RTS","RTI","BRK"}

    def fmt_operand(mode: str, lo: int, hi: int, pc: int) -> str:
        if mode == "imp" or mode == "acc": return ""
        if mode == "imm": return f"#${lo:02X}"
        if mode == "zp":  return f"${lo:02X}"
        if mode == "zpx": return f"${lo:02X},X"
        if mode == "zpy": return f"${lo:02X},Y"
        if mode == "abs": return f"${hi:02X}{lo:02X}"
        if mode == "abx": return f"${hi:02X}{lo:02X},X"
        if mode == "aby": return f"${hi:02X}{lo:02X},Y"
        if mode == "ind": return f"(${hi:02X}{lo:02X})"
        if mode == "izx": return f"(${lo:02X},X)"
        if mode == "izy": return f"(${lo:02X}),Y"
        if mode == "rel":
            offset = lo if lo < 0x80 else lo - 0x256
            return f"${pc + 2 + offset:04X}"
        return ""

    def abs_addr(mode: str, lo: int, hi: int) -> int | None:
        if mode == "abs": return (hi << 8) | lo
        if mode == "abx": return (hi << 8) | lo
        if mode == "aby": return (hi << 8) | lo
        return None

    vectors = manifest.get("interrupt_vectors", {})
    base = 0x8000
    prg_size = len(prg_data)

    entry_addrs = set()
    for vec_str in vectors.values():
        try:
            entry_addrs.add(int(vec_str, 16))
        except ValueError:
            pass

    all_instructions = {}  # addr -> (mnem, op_str, length)
    register_accesses = []
    functions = {}
    queue = list(entry_addrs)
    seen_addrs = set()

    while queue:
        addr = queue.pop()
        if addr in seen_addrs or addr < base or addr >= base + prg_size:
            continue
        # Mark start of new function if not already known
        if addr not in functions and addr in entry_addrs:
            _VEC_LABEL = {"NMI": "NMI_HANDLER", "RESET": "RESET_HANDLER", "IRQ": "IRQ_HANDLER"}
            raw_name = {int(v,16): k for k,v in vectors.items()}.get(addr, f"sub_{addr:04X}")
            vec_name = _VEC_LABEL.get(raw_name, raw_name)
            functions[f"0x{addr:04X}"] = {"name": vec_name, "start": f"0x{addr:04X}", "callers": [], "callees": []}

        while True:
            if addr in seen_addrs or addr < base or addr >= base + prg_size:
                break
            seen_addrs.add(addr)
            offset = addr - base
            if offset >= len(prg_data):
                break
            opcode = prg_data[offset]
            if opcode not in OPCODES:
                break
            mnem, mode, length = OPCODES[opcode]
            lo = prg_data[offset + 1] if length > 1 and offset + 1 < len(prg_data) else 0
            hi = prg_data[offset + 2] if length > 2 and offset + 2 < len(prg_data) else 0
            op_str = fmt_operand(mode, lo, hi, addr)
            all_instructions[addr] = (mnem, op_str, length)

            # Hardware register access detection
            target = abs_addr(mode, lo, hi)
            if target is not None and target in ALL_HW_REGS:
                access_type = "write" if mnem in ("STA","STX","STY") else "read"
                register_accesses.append({
                    "address":    f"0x{addr:04X}",
                    "hw_address": f"0x{target:04X}",
                    "hw_name":    ALL_HW_REGS[target],
                    "type":       "PPU" if target in NES_PPU_REGS else "APU",
                    "access":     access_type,
                    "mnemonic":   mnem,
                })

            # Follow control flow
            if mnem == "JSR":
                jsr_target = abs_addr(mode, lo, hi)
                if jsr_target and jsr_target not in functions:
                    functions[f"0x{jsr_target:04X}"] = {
                        "name": f"sub_{jsr_target:04X}", "start": f"0x{jsr_target:04X}",
                        "callers": [f"0x{addr:04X}"], "callees": [],
                    }
                    queue.append(jsr_target)
            elif mnem == "JMP" and mode == "abs":
                jmp_target = abs_addr(mode, lo, hi)
                if jmp_target:
                    queue.append(jmp_target)
                break
            elif mnem in BRANCHES:
                branch_offset = lo if lo < 0x80 else lo - 256
                queue.append(addr + 2 + branch_offset)
            elif mnem in TERMINATORS or mnem == "JMP":
                break

            addr += length

    # Write per-bank ASM files
    # Each NES bank uses NES addresses $8000–$BFFF or $C000–$FFFF.
    # For MMC1/switchable mappers, all switchable banks share addresses $8000–$BFFF.
    # We write all code into $8000–$FFFF space; the linker segment places each bank
    # in its own SNES bank via the .segment directive in master.asm.
    bank_size = 0x4000
    num_banks = max(1, prg_size // bank_size)
    for bank_idx in range(num_banks):
        # NES bank addresses: always $8000-$BFFF (switchable) or $C000-$FFFF (fixed)
        # Map each bank to $8000–$BFFF for switchable, $C000–$FFFF for last fixed bank
        if bank_idx == num_banks - 1:
            bank_base = 0xC000  # fixed bank
        else:
            bank_base = 0x8000  # switchable bank (same address window for all)
        bank_end = bank_base + bank_size

        lines = [f"; NES PRG Bank {bank_idx:02d}", ""]
        for addr in sorted(k for k in all_instructions
                           # Map flat disasm addr back to NES addr
                           if (base + bank_idx * bank_size) <= addr < (base + (bank_idx+1) * bank_size)):
            # Convert flat address to NES bank-relative address
            nes_addr = bank_base + (addr - (base + bank_idx * bank_size))
            mnem, op_str, _ = all_instructions[addr]
            func_key = f"0x{addr:04X}"
            if func_key in functions:
                # Named function label (valid ca65 identifier)
                lines.append(f"\n{functions[func_key]['name']}:")
            lines.append(f"    {mnem:<6} {op_str}")
        (disasm_dir / f"bank_{bank_idx:02d}.asm").write_text("\n".join(lines))

    (workspace / "disasm" / "functions.json").write_text(json.dumps(functions, indent=2))
    (workspace / "disasm" / "register_accesses.json").write_text(json.dumps(register_accesses, indent=2))
    (workspace / "disasm" / "call_graph.json").write_text(json.dumps({}, indent=2))

    print(f"[disassemble] Pure-Python 6502: {len(all_instructions)} instructions, "
          f"{len(functions)} functions, {len(register_accesses)} HW register accesses")


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
