#!/usr/bin/env python3
"""
Test the dashboard with fake pipeline events — no ROM needed.
Simulates all 8 stages with realistic timing and mock data.
"""
import json
import queue
import threading
import time
import sys
import webbrowser

# Import the dashboard app and state directly
from dashboard import app, state, STAGES


def fake_pipeline():
    """Simulate a full pipeline run with fake events."""
    time.sleep(2)  # wait for Flask

    state.pipeline_status = "running"
    state.started_at = time.time()
    state.broadcast("pipeline_start", {"rom": "roms/TestGame.nes"})

    # Fake ROM manifest (after parse_rom)
    fake_manifest = {
        "source_rom": "roms/TestGame.nes",
        "format": "iNES",
        "mapper_id": 1,
        "mapper_name": "MMC1 (SxROM)",
        "mapper_supported": True,
        "prg_rom_size_bytes": 131072,
        "chr_rom_size_bytes": 131072,
        "chr_ram": False,
        "mirroring": "Vertical",
        "battery_backed": True,
    }

    # Stage timings (seconds to simulate)
    stage_sim = {
        "parse_rom":        (0.3, [
            "[parse_rom] iNES header: mapper=1 (MMC1), PRG=128KB, CHR=128KB",
            "[parse_rom] PRG-ROM: 131072 bytes (8 x 16KB banks)",
            "[parse_rom] CHR-ROM: 131072 bytes (256 tiles)",
            "[parse_rom] Interrupt vectors: RESET=$C000, NMI=$C080, IRQ=$0000",
            "[parse_rom] Manifest written: workspace/rom_manifest.json",
        ]),
        "disassemble":      (2.0, [
            "[disassemble] Using Ghidra headless with Java 21",
            "[disassemble] Ghidra: bank 00/07 @ $8000 ... 124 lines (1.2s)",
            "[disassemble] Ghidra: bank 01/07 @ $8000 ... 98 lines (0.9s)",
            "[disassemble] Ghidra: bank 02/07 @ $8000 ... 156 lines (1.1s)",
            "[disassemble] Ghidra: bank 03/07 @ $8000 ... 87 lines (0.8s)",
            "[disassemble] Ghidra: bank 04/07 @ $8000 ... 201 lines (1.3s)",
            "[disassemble] Ghidra: bank 05/07 @ $8000 ... 112 lines (1.0s)",
            "[disassemble] Ghidra: bank 06/07 @ $8000 ... 143 lines (1.1s)",
            "[disassemble] Ghidra: bank 07/07 @ $C000 ... 352 lines (1.5s)",
            "[disassemble] 17 functions identified, 42 register accesses",
        ]),
        "translate_cpu":    (4.0, [
            "[translate_cpu] Pass 1: deterministic 6502->65816 preprocessing",
            "[translate_cpu] Pass 2: LLM translation (qwen2.5-coder:14b via Ollama)",
        ]),
        "translate_ppu":    (0.2, [
            "[translate_ppu] Generating SNES PPU wrappers (Mode 1, BG1 tilemap @ $6000)",
            "[translate_ppu] PPU_CTRL_WRITE, PPU_MASK_WRITE, PPU_SCROLL_WRITE",
            "[translate_ppu] PPU_ADDR_WRITE, PPU_DATA_WRITE, OAM_DMA_TRIGGER",
            "[translate_ppu] SNES_PPU_INIT: forced blank, NMITIMEN, VRAM layout",
            "[translate_ppu] Output: workspace/ppu_wrappers.asm (6962 bytes)",
        ]),
        "translate_mapper": (0.2, [
            "[translate_mapper] Mapper 1 (MMC1): generating bank-switch stubs",
            "[translate_mapper] MMC1 serial shift register emulation",
            "[translate_mapper] PRG bank switch: 16KB windows at $8000/$C000",
            "[translate_mapper] Output: workspace/mapper_stubs.asm (2087 bytes)",
        ]),
        "convert_graphics": (1.5, []),  # tiles handled specially
        "convert_audio":    (0.5, [
            "[convert_audio] Synthesizing BRR samples: pulse_12, pulse_25, pulse_50, pulse_75",
            "[convert_audio] Triangle wave BRR: 16 samples, looped",
            "[convert_audio] Generating SPC700 driver stub",
            "[convert_audio] Output: workspace/audio/spc_driver.asm",
        ]),
        "build_snes_rom":   (0.8, [
            "[build_snes_rom] Assembling master.asm with ca65 ...",
            "[build_snes_rom] ca65 OK -- master.o (24576 bytes)",
            "[build_snes_rom] Linking with ld65 -> output.sfc ...",
            "[build_snes_rom] Padded ROM from 196608 to 262144 bytes",
            "[build_snes_rom] Output ROM: output/output.sfc (262144 bytes)",
            "[build_snes_rom] Checksum: $A3F1  Complement: $5C0E",
        ]),
    }

    # Fake LLM function translations
    llm_functions = [
        ("NMI_HANDLER", 116, 45.2, 38, 90),
        ("RESET_HANDLER", 42, 12.1, 18, 95),
        ("ReadController", 28, 8.3, 14, 98),
        ("UpdateSprites", 67, 22.4, 30, 85),
        ("LoadLevel", 89, 31.7, 42, 82),
        ("SoundEngine", 54, 18.9, 26, 88),
    ]

    # Fake LLM output tokens
    llm_code = """.segment "BANK07"
; NMI_HANDLER -- translated from 6502 to 65816
; Original: $C080-$C0F4 (116 instructions)
NMI_HANDLER:
    SEI
    REP #$30          ; 16-bit A/X/Y
    PHA
    PHX
    PHY
    PHD
    PHB
    SEP #$20          ; 8-bit accumulator
    LDA #$00
    STA $2100         ; force blank off
    JSR PPU_CTRL_WRITE
    LDA $0200         ; sprite DMA
    JSR OAM_DMA_TRIGGER
    JSR ReadController
    JSR UpdateSprites
    JSR SoundEngine
    REP #$20
    PLB
    PLD
    PLY
    PLX
    PLA
    RTI
"""

    stage_results = []

    for stage_id, script, description, fatal in STAGES:
        sim_time, sim_lines = stage_sim.get(stage_id, (0.5, []))

        # Start stage
        with state.lock:
            state.current_stage = stage_id
            state.stages[stage_id] = {"status": "running", "elapsed": 0, "lines": []}
        state.broadcast("stage_start", {"stage": stage_id, "description": description})

        # After parse_rom: broadcast ROM info
        if stage_id == "parse_rom":
            for line in sim_lines:
                time.sleep(0.05)
                with state.lock:
                    state.stages[stage_id]["lines"].append(line)
                    state.log_lines.append(line)
                state.broadcast("log_line", {"stage": stage_id, "line": line, "elapsed": 0.1})
            time.sleep(sim_time)
            with state.lock:
                state.rom_manifest = fake_manifest
            state.broadcast("rom_info", fake_manifest)

        elif stage_id == "translate_cpu":
            # Log lines first
            for line in sim_lines:
                time.sleep(0.1)
                with state.lock:
                    state.stages[stage_id]["lines"].append(line)
                    state.log_lines.append(line)
                state.broadcast("log_line", {"stage": stage_id, "line": line, "elapsed": 0.2})

            # Simulate per-function LLM translation with progress
            with state.lock:
                state.llm_tokens.clear()

            for i, (name, instrs, secs, lines, conf) in enumerate(llm_functions):
                progress = f"[translate_cpu] [{i+1}/{len(llm_functions)}] {name} ({instrs} instrs) ..."
                with state.lock:
                    state.stages[stage_id]["lines"].append(progress)
                    state.log_lines.append(progress)
                state.broadcast("log_line", {"stage": stage_id, "line": progress, "elapsed": 1.0})

                # Stream LLM tokens for first function only (demo)
                if i == 0:
                    for ch in llm_code:
                        with state.lock:
                            state.llm_tokens.append(ch)
                        state.broadcast("llm_token", {"token": ch})
                        time.sleep(0.008)  # ~125 tokens/sec

                time.sleep(0.3)
                done = f"[translate_cpu]       OK ({secs}s, {lines} lines, confidence={conf}%)"
                with state.lock:
                    state.stages[stage_id]["lines"].append(done)
                    state.log_lines.append(done)
                state.broadcast("log_line", {"stage": stage_id, "line": done, "elapsed": 2.0})

        elif stage_id == "convert_graphics":
            # Simulate tile progress
            total_tiles = 4096
            for batch in range(0, total_tiles + 1, 256):
                current = min(batch, total_tiles)
                if current == 0:
                    current = 256
                line = f"[convert_graphics]   {current}/{total_tiles} tiles converted ({current * 32} SNES bytes)"
                with state.lock:
                    state.stages[stage_id]["lines"].append(line)
                    state.log_lines.append(line)
                    state.tile_progress = {"current": current, "total": total_tiles}
                state.broadcast("log_line", {"stage": stage_id, "line": line, "elapsed": 0.5})
                state.broadcast("tile_progress", {"current": current, "total": total_tiles})
                time.sleep(0.08)

        else:
            # Generic: emit log lines with spacing
            for line in sim_lines:
                time.sleep(sim_time / max(len(sim_lines), 1))
                with state.lock:
                    state.stages[stage_id]["lines"].append(line)
                    state.log_lines.append(line)
                state.broadcast("log_line", {"stage": stage_id, "line": line, "elapsed": 0.5})

        # End stage
        elapsed = sim_time
        with state.lock:
            state.stages[stage_id]["status"] = "success"
            state.stages[stage_id]["elapsed"] = elapsed
        state.broadcast("stage_end", {"stage": stage_id, "status": "success", "elapsed": elapsed})
        stage_results.append({"stage": stage_id, "success": True,
                               "returncode": 0, "elapsed_seconds": elapsed})

        time.sleep(0.3)  # brief pause between stages

    # Pipeline complete
    fake_report = {
        "input_rom": "roms/TestGame.nes",
        "output_rom": "output/output.sfc",
        "fidelity_estimate": "PARTIAL",
        "total_elapsed_seconds": round(sum(s["elapsed_seconds"] for s in stage_results), 2),
        "warnings": ["Stage 'convert_audio' failed"],
        "stages": stage_results,
    }
    with state.lock:
        state.build_report = fake_report
    state.pipeline_status = "complete"
    state.current_stage = None
    state.broadcast("pipeline_complete", fake_report)
    print("[test] Fake pipeline complete!", flush=True)


def main():
    port = 5555
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    # Start fake pipeline thread
    t = threading.Thread(target=fake_pipeline, daemon=True)
    t.start()

    # Auto-open browser
    def open_browser():
        time.sleep(2)
        webbrowser.open(f"http://localhost:{port}")
    threading.Thread(target=open_browser, daemon=True).start()

    print(f"\n  rompipe dashboard (TEST MODE): http://localhost:{port}\n", flush=True)
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
