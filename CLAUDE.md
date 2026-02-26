# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Fully automated NES → SNES ROM port pipeline for Apple Silicon macOS. Input: any `.nes` ROM file. Output: a playable `.sfc` SNES ROM with enhanced graphics (16-bit color) and stereo SPC700 audio.

**Key constraints:**
- All tooling runs locally via CLI — no cloud services except the Anthropic API
- `ANTHROPIC_API_KEY` must be set in `.env` for LLM-assisted translation
- `ca65`/`ld65` (cc65 toolchain) must be installed for final assembly
- Ghidra is the primary disassembler; `capstone` is the fallback

## Environment Prerequisites

```bash
# Python dependencies
pip3 install -r requirements.txt

# Assembler/linker (ARM64 native via Homebrew)
brew install cc65

# Disassembler (ARM64 JVM via Homebrew)
brew install --cask ghidra

# Copy .env template and add your API key
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY=sk-ant-...
```

Required for ComfyUI upscaling (optional, `--upscale` flag only):
- ComfyUI running locally on port 8188 (`python3 main.py --force-fp16` in ComfyUI dir)
- SDXL checkpoint → `ComfyUI/models/checkpoints/`
- ControlNet Tile model → `ComfyUI/models/controlnet/`

## Running the Pipeline

```bash
# Full port (recommended)
python3 main.py game.nes

# With AI upscaled sprites (requires ComfyUI on port 8188)
python3 main.py game.nes --upscale

# Skip audio conversion
python3 main.py game.nes --skip-audio

# Disable LLM pass (faster, lower fidelity)
python3 main.py game.nes --no-llm

# Run a single stage (for debugging)
python3 parse_rom.py game.nes
python3 disassemble.py
python3 translate_cpu.py --no-llm
python3 translate_ppu.py
python3 translate_mapper.py
python3 convert_graphics.py
python3 convert_audio.py
python3 build_snes_rom.py
```

## Architecture

Eight Python scripts with strict execution order:

1. **`parse_rom.py`** — Parses iNES 1.0/NES 2.0 header, extracts PRG-ROM and CHR-ROM, identifies mapper. Output: `workspace/rom_manifest.json`, `workspace/prg_rom.bin`, `workspace/chr_rom.bin`

2. **`disassemble.py`** — Ghidra headless disassembly via `scripts/NESAnalyzer.java`. Exports function boundaries, call graph, and all hardware register ($2000–$4017) access sites. Fallback: `capstone` recursive descent. Output: `workspace/disasm/`

3. **`translate_cpu.py`** — Two-pass 6502→65816 translation. Pass 1: deterministic pre-processor (opcode substitution, hardware register access → JSR wrapper replacement, 65816 init preamble injection). Pass 2: Claude API for hard cases (NMI handler, indirect jumps, self-modifying code, cross-bank calls). Output: `workspace/translated/`

4. **`translate_ppu.py`** — Generates ca65 ASM wrapper subroutines for all NES PPU register accesses ($2000–$2007, $4014). Implements SNES PPU equivalents with two-write latch protocols, DMA channel setup, etc. Output: `workspace/ppu_wrappers.asm`, `workspace/ppu_init.asm`

5. **`translate_mapper.py`** — Generates SNES-side mapper bank-switch stubs and LoROM bank layout. Supports NROM (0), MMC1 (1), UNROM (2), CNROM (3), MMC3 (4). Unsupported mappers get diagnostic stubs. Output: `workspace/mapper_stubs.asm`, `workspace/bank_layout.json`

6. **`convert_graphics.py`** — Converts CHR-ROM 2bpp NES tiles to SNES 4bpp planar format (32 bytes/tile). Converts NES palette to SNES 15-bit BGR CGRAM data. Output: `workspace/chr_snes.bin`, `workspace/palette_snes.bin`

7. **`convert_audio.py`** — Synthesizes BRR samples (pulse×4 duty cycles, triangle, noise, DMC). Uses Claude API to identify music engine data tables. Generates SPC700 driver (ca65 ASM) for SNES audio CPU. Output: `workspace/audio/`

8. **`build_snes_rom.py`** — Generates `master.asm` and `lorom.cfg`, assembles with `ca65`/`ld65`, embeds CHR data, writes SNES LoROM header, computes checksum. Output: `output/output.sfc`, `output/build_report.json`

**`main.py`** orchestrates all 8 stages via `subprocess`. Fatal stages: `parse_rom` and `build_snes_rom`. All others degrade gracefully.

## Key Technical Decisions

- **LoROM format**: 32KB banks at `$8000–$FFFF` per SNES bank — mirrors NES PRG window layout exactly
- **65816 compatibility mode**: `SEP #$30` keeps A/X/Y at 8-bit; Direct Page = `$0000` preserves zero-page semantics
- **Hardware register strategy**: All NES `$2000–$401F` accesses pre-replaced with `JSR WRAPPER_NAME` stubs in Pass 1, never passed to LLM
- **LLM routing**: `claude-opus-4-6` for NMI/mapper IRQ handlers; `claude-sonnet-4-6` for all other functions

## Supported Mappers

| Mapper | Name   | Coverage |
|--------|--------|----------|
| 0      | NROM   | ~10% of titles |
| 1      | MMC1   | ~28% of titles |
| 2      | UNROM  | ~11% of titles |
| 3      | CNROM  | ~6% of titles  |
| 4      | MMC3   | ~24% of titles |

Combined: ~79% of commercially released NES titles.

## Workspace Layout

```
workspace/          # auto-created, gitignored
├── rom_manifest.json
├── prg_rom.bin / chr_rom.bin
├── disasm/         # bank_NN.asm, functions.json, register_accesses.json
├── translated/     # bank_NN_65816.asm, translation_log.json
├── tiles/          # tile_NNNN_nes.png (+ _hd.png if --upscale)
├── audio/          # spc_driver.asm, brr_samples/*.brr
├── ppu_wrappers.asm / ppu_init.asm / mapper_stubs.asm
├── bank_layout.json / master.asm / lorom.cfg
output/             # gitignored
├── output.sfc
├── build_report.json
└── pipeline.log
```
