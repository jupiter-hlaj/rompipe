#!/usr/bin/env python3
"""
Stage 1: parse_rom.py
Parses an iNES 1.0 or NES 2.0 ROM file, extracts PRG-ROM, CHR-ROM,
and writes a manifest JSON consumed by all downstream stages.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

INES_MAGIC = b"NES\x1a"

MAPPER_NAMES = {
    0: "NROM",
    1: "MMC1 (SxROM)",
    2: "UNROM",
    3: "CNROM",
    4: "MMC3 (TxROM)",
    5: "MMC5 (ExROM)",
    7: "AxROM",
    9: "MMC2 (PxROM)",
    10: "MMC4 (FxROM)",
    11: "ColorDreams",
    66: "GxROM",
    71: "Camerica",
    94: "UN1ROM",
    180: "UNROM (variant)",
}

SUPPORTED_MAPPERS = {0, 1, 2, 3, 4}


def parse_ines_header(data: bytes) -> dict:
    if data[:4] != INES_MAGIC:
        raise ValueError(f"Not a valid iNES ROM (magic bytes missing)")

    prg_size_16kb = data[4]
    chr_size_8kb = data[5]
    flags6 = data[6]
    flags7 = data[7]

    # Detect NES 2.0 format
    is_nes2 = (flags7 & 0x0C) == 0x08

    mapper_id = (flags6 >> 4) | (flags7 & 0xF0)
    mirroring = "four_screen" if (flags6 & 0x08) else ("vertical" if (flags6 & 0x01) else "horizontal")
    has_trainer = bool(flags6 & 0x04)
    battery_backed = bool(flags6 & 0x02)

    prg_rom_size = prg_size_16kb * 16 * 1024
    chr_rom_size = chr_size_8kb * 8 * 1024
    chr_ram = (chr_size_8kb == 0)

    prg_ram_size = 8192  # default; NES 2.0 can specify exactly
    if is_nes2:
        prg_ram_size = 64 << ((data[10] & 0x0F) or 0)

    # Calculate offsets into the file
    header_size = 16
    trainer_size = 512 if has_trainer else 0
    prg_offset = header_size + trainer_size
    chr_offset = prg_offset + prg_rom_size

    return {
        "format": "NES2" if is_nes2 else "iNES1",
        "mapper_id": mapper_id,
        "mapper_name": MAPPER_NAMES.get(mapper_id, f"Unknown (#{mapper_id})"),
        "mapper_supported": mapper_id in SUPPORTED_MAPPERS,
        "prg_rom_banks": prg_size_16kb,
        "prg_rom_size_bytes": prg_rom_size,
        "chr_rom_banks": chr_size_8kb,
        "chr_rom_size_bytes": chr_rom_size,
        "chr_ram": chr_ram,
        "prg_ram_size_bytes": prg_ram_size,
        "mirroring": mirroring,
        "battery_backed": battery_backed,
        "trainer_present": has_trainer,
        "tv_system": "NTSC",
        "prg_offset": prg_offset,
        "chr_offset": chr_offset,
        "trainer_offset": header_size if has_trainer else None,
    }


def extract_interrupt_vectors(prg_rom: bytes) -> dict:
    # Vectors are always in the last 16KB bank at the very end
    last_bank = prg_rom[-0x4000:]
    nmi_vec  = struct.unpack_from("<H", last_bank, 0x3FFA)[0]
    rst_vec  = struct.unpack_from("<H", last_bank, 0x3FFC)[0]
    irq_vec  = struct.unpack_from("<H", last_bank, 0x3FFE)[0]
    return {
        "NMI":   f"0x{nmi_vec:04X}",
        "RESET": f"0x{rst_vec:04X}",
        "IRQ":   f"0x{irq_vec:04X}",
    }


def parse_rom(rom_path: Path, workspace: Path) -> dict:
    workspace.mkdir(parents=True, exist_ok=True)
    data = rom_path.read_bytes()

    if len(data) < 16:
        raise ValueError("File too small to be a valid NES ROM")

    header = parse_ines_header(data)

    prg_start = header["prg_offset"]
    prg_end   = prg_start + header["prg_rom_size_bytes"]
    chr_start = header["chr_offset"]
    chr_end   = chr_start + header["chr_rom_size_bytes"]

    prg_rom = data[prg_start:prg_end]
    chr_rom = data[chr_start:chr_end] if not header["chr_ram"] else b""
    trainer = data[header["trainer_offset"]: header["trainer_offset"] + 512] if header["trainer_present"] else b""

    # Write binary segments
    (workspace / "prg_rom.bin").write_bytes(prg_rom)
    (workspace / "chr_rom.bin").write_bytes(chr_rom)
    if trainer:
        (workspace / "trainer.bin").write_bytes(trainer)

    vectors = extract_interrupt_vectors(prg_rom)
    manifest = {**header, "interrupt_vectors": vectors, "source_rom": str(rom_path.resolve())}

    manifest_path = workspace / "rom_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Parse NES ROM and extract segments")
    parser.add_argument("rom", help="Path to .nes ROM file")
    parser.add_argument("--workspace", default="workspace", help="Working directory (default: workspace/)")
    args = parser.parse_args()

    rom_path  = Path(args.rom)
    workspace = Path(args.workspace)

    if not rom_path.exists():
        print(f"ERROR: ROM file not found: {rom_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[parse_rom] Parsing: {rom_path.name}")
    manifest = parse_rom(rom_path, workspace)

    print(f"[parse_rom] Mapper:    {manifest['mapper_name']} (#{manifest['mapper_id']})")
    print(f"[parse_rom] PRG-ROM:   {manifest['prg_rom_size_bytes'] // 1024} KB ({manifest['prg_rom_banks']} x 16KB banks)")
    print(f"[parse_rom] CHR-ROM:   {manifest['chr_rom_size_bytes'] // 1024} KB" if not manifest["chr_ram"] else "[parse_rom] CHR-RAM:   (no CHR-ROM, uses RAM)")
    print(f"[parse_rom] Mirroring: {manifest['mirroring']}")
    print(f"[parse_rom] Vectors:   NMI={manifest['interrupt_vectors']['NMI']}  RESET={manifest['interrupt_vectors']['RESET']}  IRQ={manifest['interrupt_vectors']['IRQ']}")

    if not manifest["mapper_supported"]:
        print(f"[parse_rom] WARNING: Mapper #{manifest['mapper_id']} is not in the supported set. "
              "Translation will proceed with best-effort stubs.", file=sys.stderr)

    print(f"[parse_rom] Manifest written to {workspace}/rom_manifest.json")


if __name__ == "__main__":
    main()
