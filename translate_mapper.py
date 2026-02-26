#!/usr/bin/env python3
"""
Stage 5: translate_mapper.py
Generates SNES-side mapper bank-switching stubs and LoROM bank layout.
Supports NROM (0), MMC1 (1), UNROM (2), CNROM (3), MMC3 (4).
All other mappers get a diagnostic stub.

Output: workspace/mapper_stubs.asm, workspace/bank_layout.json
"""
import argparse
import json
import sys
from pathlib import Path


NROM_ASM = """\
; =============================================================================
; mapper_stubs.asm  —  Mapper 0 (NROM)
; No bank switching — PRG is fixed. No stubs required.
; =============================================================================
.setcpu "65816"
.segment "CODE"
; NROM: all PRG banks fixed in LoROM layout. No mapper write handler needed.
MAPPER_INIT:
    RTS
"""

MMC1_ASM = """\
; =============================================================================
; mapper_stubs.asm  —  Mapper 1 (MMC1 / SxROM)
; 5-bit serial shift register. Writes to $8000–$FFFF load one bit at a time.
; On the 5th write, the value is applied to control/chr/prg bank registers.
; =============================================================================
.setcpu "65816"
.segment "ZEROPAGE"
MMC1_SHIFT:      .res 1   ; shift register accumulator (bits loaded LSB first)
MMC1_SHIFT_CNT:  .res 1   ; count of bits loaded (0–4)
MMC1_CONTROL:    .res 1   ; shadow of MMC1 control register
MMC1_PRG_BANK:   .res 1   ; current PRG bank selection

.segment "CODE"

MAPPER_INIT:
    STZ MMC1_SHIFT
    STZ MMC1_SHIFT_CNT
    LDA #$0C            ; MMC1 default control: PRG fixed at $C000, 32K CHR
    STA MMC1_CONTROL
    RTS

; Called when NES code writes to $8000–$FFFF (mapper register space).
; A = data byte written, X = address high byte (bank).
; Only bit 0 of A is loaded into the shift register.
MMC1_WRITE:
    ; Reset on bit 7 set
    BIT #$80
    BNE @reset
    ; Load bit 0 into shift register (LSB first)
    LSR A               ; bit 0 → carry
    LDA MMC1_SHIFT
    ROR A               ; carry → bit 7, then shift right builds LSB-first
    STA MMC1_SHIFT      ; NOTE: after 5 writes this will be in bits 4–0
    INC MMC1_SHIFT_CNT
    LDA MMC1_SHIFT_CNT
    CMP #5
    BNE @done
    ; 5th write: apply
    JSR MMC1_APPLY
    STZ MMC1_SHIFT
    STZ MMC1_SHIFT_CNT
@done:
    RTS
@reset:
    STZ MMC1_SHIFT
    STZ MMC1_SHIFT_CNT
    RTS

MMC1_APPLY:
    ; Address of register determined by the write address high nibble:
    ; $8000–$9FFF = control, $A000–$BFFF = CHR bank 0,
    ; $C000–$DFFF = CHR bank 1, $E000–$FFFF = PRG bank
    ; In the SNES translation we approximate by tracking writes in order.
    ; Full fidelity requires the translated code to pass address context.
    LDA MMC1_SHIFT
    AND #$0F            ; mask to 4 bits (PRG bank)
    STA MMC1_PRG_BANK
    ; TODO: signal SNES to remap bank pointers in indirect jump table
    RTS
"""

UNROM_ASM = """\
; =============================================================================
; mapper_stubs.asm  —  Mapper 2 (UNROM)
; Single register: write to $8000–$FFFF selects switchable PRG bank at $8000.
; $C000–$FFFF is always fixed to the last PRG bank.
; =============================================================================
.setcpu "65816"
.segment "ZEROPAGE"
UNROM_PRG_BANK: .res 1   ; current switchable bank (maps to $8000–$BFFF)

.segment "CODE"
MAPPER_INIT:
    STZ UNROM_PRG_BANK
    RTS

; A = bank number (0-based)
UNROM_WRITE:
    AND #$07            ; mask to 3 bits
    STA UNROM_PRG_BANK
    ; In LoROM: bank $01 = PRG bank 0, bank $02 = PRG bank 1, etc.
    ; The translated code uses indirect JSR table — update target bank here.
    RTS
"""

CNROM_ASM = """\
; =============================================================================
; mapper_stubs.asm  —  Mapper 3 (CNROM)
; CHR bank switching only. PRG is fixed (NROM-style). Write to $8000–$FFFF
; selects which 8KB CHR bank maps to PPU $0000–$1FFF.
; =============================================================================
.setcpu "65816"
.segment "ZEROPAGE"
CNROM_CHR_BANK: .res 1   ; current CHR bank selection

.segment "CODE"
MAPPER_INIT:
    STZ CNROM_CHR_BANK
    RTS

; A = CHR bank number (0-based)
CNROM_WRITE:
    AND #$03            ; 2 bits, 4 banks max
    STA CNROM_CHR_BANK
    ; Trigger VRAM reload: re-copy selected CHR bank from ROM to VRAM $0000
    JSR RELOAD_CHR_VRAM
    RTS

; Re-load the selected CHR bank into SNES VRAM $0000
; Each CHR bank = 512 NES tiles = 512 × 32 bytes = 16KB
RELOAD_CHR_VRAM:
    ; Set VRAM destination to $0000
    STZ $2115           ; VMAIN: inc by 1
    STZ $2116           ; VMADDL
    STZ $2117           ; VMADDH
    ; DMA from ROM bank containing CHR data (bank_layout determines source)
    ; TODO: parameterize source address by CNROM_CHR_BANK
    RTS
"""

MMC3_ASM = """\
; =============================================================================
; mapper_stubs.asm  —  Mapper 4 (MMC3 / TxROM)
; 8 independently switchable banks. Scanline IRQ counter.
; Register select at $8000 (even), data at $8001 (even+1).
; PRG mode at $A000, CHR mode at $A000.
; =============================================================================
.setcpu "65816"
.segment "ZEROPAGE"
MMC3_REG_SEL:   .res 1   ; bank register selector (bits 0–2 = reg, bit 7 = PRG mode, bit 6 = CHR mode)
MMC3_BANKS:     .res 8   ; bank register values [R0–R7]
MMC3_IRQ_LATCH: .res 1   ; IRQ counter latch value
MMC3_IRQ_CNTLO: .res 1   ; IRQ counter low
MMC3_IRQ_EN:    .res 1   ; IRQ enabled flag

.segment "CODE"
MAPPER_INIT:
    STZ MMC3_REG_SEL
    LDX #7
@clear:
    STZ MMC3_BANKS,X
    DEX
    BPL @clear
    STZ MMC3_IRQ_EN
    RTS

; Bank select register write ($8000 even)
MMC3_BANK_SEL:
    STA MMC3_REG_SEL
    RTS

; Bank data write ($8001 even+1)
MMC3_BANK_DATA:
    LDX MMC3_REG_SEL
    AND #$07
    TAX
    LDA $00,S           ; retrieve A before indexing  ; REVIEW: check stack usage
    STA MMC3_BANKS,X
    RTS

; IRQ latch write ($C000 even)
MMC3_IRQ_LATCH_WRITE:
    STA MMC3_IRQ_LATCH
    RTS

; IRQ reload write ($C001 even+1)
MMC3_IRQ_RELOAD:
    LDA MMC3_IRQ_LATCH
    STA MMC3_IRQ_CNTLO
    RTS

; IRQ disable ($E000 even)
MMC3_IRQ_DISABLE:
    STZ MMC3_IRQ_EN
    RTS

; IRQ enable ($E001 even+1)
MMC3_IRQ_ENABLE:
    LDA #$01
    STA MMC3_IRQ_EN
    ; Configure SNES H-IRQ to approximate scanline timing
    LDA #$08            ; H-IRQ enable bit
    STA $4200
    RTS
"""

UNSUPPORTED_ASM = """\
; =============================================================================
; mapper_stubs.asm  —  UNSUPPORTED MAPPER
; This mapper is not in the supported set. The ROM will not boot correctly.
; Refer to build_report.json for details.
; =============================================================================
.setcpu "65816"
.segment "CODE"
MAPPER_INIT:
    BRK                 ; halt — unsupported mapper
    RTS
"""

MAPPER_ASM = {
    0: NROM_ASM,
    1: MMC1_ASM,
    2: UNROM_ASM,
    3: CNROM_ASM,
    4: MMC3_ASM,
}

SUPPORTED_MAPPERS = set(MAPPER_ASM.keys())


def build_bank_layout(manifest: dict) -> dict:
    """Build a LoROM bank assignment map from ROM manifest."""
    prg_banks_16kb = manifest["prg_rom_banks"]
    # Each 16KB NES bank maps to one 32KB LoROM slot (with the upper 16KB mirrored/padded)
    # or we can pack two 16KB banks into one 32KB LoROM bank
    bank_map = []
    lorom_bank = 1  # start at SNES bank $01 (bank $00 is system/wrappers)
    for i in range(prg_banks_16kb):
        bank_map.append({
            "snes_bank": f"0x{lorom_bank:02X}",
            "prg_source_offset": i * 0x4000,
            "prg_source_size": 0x4000,
            "nes_bank_num": i,
        })
        lorom_bank += 1

    return {
        "rom_format": "LoROM",
        "total_snes_banks": lorom_bank,
        "bank_map": bank_map,
        "system_bank": "0x00",
        "audio_bank": f"0x{lorom_bank:02X}",
        "fixed_last_bank": f"0x{lorom_bank + 1:02X}",
    }


def main():
    parser = argparse.ArgumentParser(description="Generate SNES mapper bank-switch stubs")
    parser.add_argument("--workspace", default="workspace")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    manifest_path = workspace / "rom_manifest.json"
    if not manifest_path.exists():
        print("ERROR: rom_manifest.json not found — run parse_rom.py first", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text())
    mapper_id = manifest["mapper_id"]

    asm = MAPPER_ASM.get(mapper_id, UNSUPPORTED_ASM)
    if mapper_id not in SUPPORTED_MAPPERS:
        print(f"[translate_mapper] WARNING: Mapper #{mapper_id} not supported — writing diagnostic stub",
              file=sys.stderr)

    stubs_path = workspace / "mapper_stubs.asm"
    stubs_path.write_text(asm)
    print(f"[translate_mapper] Written: {stubs_path} (Mapper #{mapper_id}: {manifest['mapper_name']})")

    layout = build_bank_layout(manifest)
    layout_path = workspace / "bank_layout.json"
    layout_path.write_text(json.dumps(layout, indent=2))
    print(f"[translate_mapper] Written: {layout_path} ({layout['total_snes_banks']} SNES banks)")


if __name__ == "__main__":
    main()
