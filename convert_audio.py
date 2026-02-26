#!/usr/bin/env python3
"""
Stage 7: convert_audio.py
Converts NES APU audio to SNES SPC700 format:
1. Uses Claude API to identify music engine and data tables in the disassembly.
2. Synthesizes BRR samples for NES APU channels (pulse, triangle, noise, DMC).
3. Generates a SPC700 driver (ca65 ASM) that receives note commands from the 65816 CPU.

Output:
  workspace/audio/spc_driver.asm
  workspace/audio/brr_samples/*.brr
  workspace/audio/music_data.bin   (if music tables identified)
"""
import argparse
import json
import os
import struct
import sys
from pathlib import Path

try:
    import numpy as np
except ImportError:
    np = None

try:
    import anthropic
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    anthropic = None

# NES APU → SNES SPC700 channel mapping
CHANNEL_MAP = {
    "pulse1":   0,   # DSP voice 0
    "pulse2":   1,   # DSP voice 1
    "triangle": 2,   # DSP voice 2
    "noise":    3,   # DSP voice 3 (uses DSP native noise, NON bit)
    "dmc":      4,   # DSP voice 4 (BRR-encoded PCM)
}

# NES APU pulse frequency: F = 1789773 / (16 * (period + 1))
# SNES DSP pitch: P = F * 4096 / 32000
def nes_period_to_snes_pitch(nes_period: int) -> int:
    if nes_period < 0:
        return 0
    freq_hz = 1789773.0 / (16.0 * (nes_period + 1))
    snes_pitch = int(freq_hz * 4096.0 / 32000.0)
    return min(snes_pitch, 0x3FFF)  # 14-bit max


# ---------------------------------------------------------------------------
# BRR encoding
# ---------------------------------------------------------------------------
def pcm_to_brr(samples: "np.ndarray", loop: bool = True) -> bytes:
    """
    Encode a PCM float32 array (range -1.0 to +1.0) as SNES BRR.
    Pads to a multiple of 16 samples.
    Each BRR block: 1 header byte + 8 data bytes (16 nibbles = 16 samples).
    """
    if np is None:
        return b"\x00" * 9  # silent stub

    # Pad to multiple of 16
    n = len(samples)
    padded = int(np.ceil(n / 16)) * 16
    buf = np.zeros(padded, dtype=np.float32)
    buf[:n] = samples

    blocks = padded // 16
    output = bytearray()
    p1, p2 = 0, 0  # filter state

    for b in range(blocks):
        block = buf[b * 16: b * 16 + 16]
        best_err = float("inf")
        best_header = 0
        best_nibbles = None

        # Try all shift (0–12) and filter (0–3) combinations
        for shift in range(13):
            for filt in range(4):
                nibbles = []
                sp1, sp2 = p1, p2
                err_sum = 0.0
                valid = True

                for s in block:
                    target_i16 = int(s * 32767.0)
                    # Predict based on filter
                    if   filt == 0: pred = 0
                    elif filt == 1: pred = sp1
                    elif filt == 2: pred = sp1 * 2 - sp1 * 15 // 16 - sp2 + sp2 * 15 // 16
                    else:           pred = sp1 * 2 - sp1 * 13 // 16 - sp2 + sp2 * 3 // 16

                    delta = target_i16 - pred
                    # Quantize to nibble
                    nib = delta >> (shift + 1)
                    nib = max(-8, min(7, nib))
                    # Reconstruct
                    reconstructed = (nib << (shift + 1)) + pred
                    reconstructed = max(-32768, min(32767, reconstructed))
                    err_sum += (target_i16 - reconstructed) ** 2
                    nibbles.append(nib & 0xF)
                    sp2 = sp1
                    sp1 = reconstructed

                if err_sum < best_err:
                    best_err = err_sum
                    is_last = (b == blocks - 1)
                    best_header = ((shift & 0xF) << 4) | ((filt & 0x3) << 2) | \
                                  (0x02 if (is_last and loop) else 0) | \
                                  (0x01 if is_last else 0)
                    best_nibbles = nibbles
                    # Update filter state
                    sp1_final, sp2_final = sp1, sp2

        # Pack 16 nibbles into 8 bytes
        output.append(best_header)
        for i in range(0, 16, 2):
            byte = ((best_nibbles[i] & 0xF) << 4) | (best_nibbles[i + 1] & 0xF)
            output.append(byte)

        p1, p2 = sp1_final, sp2_final

    return bytes(output)


def generate_pulse_brr(duty_cycle: float) -> bytes:
    """Generate a single-period BRR sample for an NES pulse channel."""
    if np is None:
        return b"\x00" * 9
    # 16 samples per period (one BRR block)
    samples = np.zeros(16, dtype=np.float32)
    threshold = max(1, int(16 * duty_cycle))
    samples[:threshold] = 0.75
    samples[threshold:] = -0.75
    return pcm_to_brr(samples, loop=True)


def generate_triangle_brr() -> bytes:
    """Generate BRR for NES triangle wave (linear ramp up and down)."""
    if np is None:
        return b"\x00" * 9
    samples = np.concatenate([
        np.linspace(-0.75, 0.75, 8, dtype=np.float32),
        np.linspace(0.75, -0.75, 8, dtype=np.float32),
    ])
    return pcm_to_brr(samples, loop=True)


def decode_dmc_pcm(prg_data: bytes, start_offset: int, length: int) -> "np.ndarray":
    """Decode NES DMC 1-bit delta PCM to float32 samples."""
    if np is None:
        return np.array([], dtype=np.float32) if np else []
    output_level = 64  # initial output level
    samples = []
    byte_count = min(length, len(prg_data) - start_offset)
    for i in range(byte_count):
        byte = prg_data[start_offset + i]
        for bit in range(8):
            if (byte >> bit) & 1:
                output_level = min(127, output_level + 2)
            else:
                output_level = max(0, output_level - 2)
            samples.append(output_level / 127.0 * 2.0 - 1.0)
    return np.array(samples, dtype=np.float32)


def identify_music_engine(workspace: Path, manifest: dict) -> dict:
    """Use Claude API to locate music data tables in the disassembly."""
    if anthropic is None:
        return {"identified": False, "reason": "anthropic package not installed"}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"identified": False, "reason": "ANTHROPIC_API_KEY not set"}

    disasm_dir = workspace / "disasm"
    nmi_vec = int(manifest["interrupt_vectors"]["NMI"], 16)

    # Find the bank containing the NMI handler
    nmi_bank = nmi_vec >> 14  # 16KB bank index
    bank_file = disasm_dir / f"bank_{nmi_bank:02d}.asm"
    if not bank_file.exists():
        # Try the last bank (fixed bank)
        bank_files = sorted(disasm_dir.glob("bank_*.asm"))
        bank_file = bank_files[-1] if bank_files else None

    if not bank_file:
        return {"identified": False, "reason": "No disassembly bank files found"}

    asm_text = bank_file.read_text()[:8000]  # limit context size

    client = anthropic.Anthropic(api_key=api_key)
    try:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=(
                "You are an NES audio engineer analyzing 6502 assembly code. "
                "Identify music engine components. Respond in JSON only."
            ),
            messages=[{
                "role": "user",
                "content": (
                    f"ROM: {manifest.get('source_rom', 'unknown')}, "
                    f"Mapper: {manifest.get('mapper_name', 'unknown')}\n"
                    f"NMI vector: {manifest['interrupt_vectors']['NMI']}\n\n"
                    "Analyze this NES disassembly and find:\n"
                    "1. The APU write subroutines (functions that write to $4000–$4013)\n"
                    "2. Note frequency table addresses (if any)\n"
                    "3. Pattern/sequence table addresses (if any)\n"
                    "4. Tempo counter or frame delay logic\n\n"
                    "Respond as JSON: {\"apu_write_addrs\": [], \"freq_table_addr\": null, "
                    "\"pattern_table_addr\": null, \"tempo_addr\": null, \"notes\": \"\"}\n\n"
                    f"Disassembly:\n{asm_text}"
                ),
            }],
        )
        result = json.loads(msg.content[0].text)
        result["identified"] = True
        return result
    except Exception as e:
        return {"identified": False, "reason": str(e)}


SPC_DRIVER_ASM = """\
; =============================================================================
; spc_driver.asm  —  SNES SPC700 audio driver
; Auto-generated by convert_audio.py
;
; Communication protocol with the 65816 main CPU ($2140–$2143 APU registers):
;   $2140 (APUIO0): command byte
;   $2141 (APUIO1): channel index (0–4)
;   $2142 (APUIO2): data low byte (pitch low / note)
;   $2143 (APUIO3): data high byte (pitch high / volume)
;
; Commands:
;   $01 = NOTE_ON   (ch, pitch_lo, pitch_hi)
;   $02 = NOTE_OFF  (ch, 0, 0)
;   $03 = SET_VOL   (ch, vol_l, vol_r)
;   $FF = RESET_ALL
; =============================================================================

.setcpu "spc700"

; SPC700 register addresses
DSP_ADDR  = $F2
DSP_DATA  = $F3
APUIO0    = $F4         ; read: from 65816 main CPU
APUIO1    = $F5
APUIO2    = $F6
APUIO3    = $F7
APUIO_OUT0 = $F4        ; write: to 65816 main CPU
TIMER0    = $FA
TIMER0_OUT = $FD

; DSP register base offsets per voice (voice N = N*$10)
DSP_VOL_L  = $00        ; left volume
DSP_VOL_R  = $01        ; right volume
DSP_PITCH_L = $02       ; pitch low
DSP_PITCH_H = $03       ; pitch high
DSP_SRCN   = $04        ; source number (BRR sample index)
DSP_ADSR1  = $05
DSP_ADSR2  = $06
DSP_GAIN   = $07
DSP_ENVX   = $08
DSP_OUTX   = $09
; Global DSP registers
DSP_MVOL_L = $0C        ; master volume L
DSP_MVOL_R = $1C        ; master volume R
DSP_KON    = $4C        ; key-on
DSP_KOFF   = $5C        ; key-off
DSP_NON    = $3C        ; noise enable
DSP_DIR    = $5D        ; sample directory page

; Zero page
.zeropage
CMD:      .byte 0
CH:       .byte 0
DATA_L:   .byte 0
DATA_H:   .byte 0
LAST_CMD: .byte 0

.segment "SPCCODE"

; --- SPC700 entry point ---
SPC_INIT:
    ; Set master volume
    MOV A, #$7F
    MOV $F2, #DSP_MVOL_L
    MOV $F3, A
    MOV $F2, #DSP_MVOL_R
    MOV $F3, A

    ; Set sample directory (page $04 in SPC RAM)
    MOV $F2, #DSP_DIR
    MOV $F3, #$04

    ; Enable noise for channel 3 (NES noise channel)
    MOV $F2, #DSP_NON
    MOV $F3, #$08       ; bit 3 = voice 3

    ; Configure timer 0 at ~120Hz (SPC clock = 1.024 MHz, /8192 = 125Hz)
    MOV $FA, #$00       ; timer 0 period = 256 (counts up to 256 then fires)
    MOV $F1, #$01       ; enable timer 0

    ; Signal ready to main CPU
    MOV $F4, #$AA       ; ready handshake

MAIN_LOOP:
    ; Poll for command from main CPU
    MOV A, $F4          ; read APUIO0
    CMP A, LAST_CMD
    BEQ MAIN_LOOP       ; no new command

    MOV LAST_CMD, A
    MOV CMD, A
    MOV A, $F5
    MOV CH, A
    MOV A, $F6
    MOV DATA_L, A
    MOV A, $F7
    MOV DATA_H, A

    ; Acknowledge
    MOV $F4, CMD

    ; Dispatch
    MOV A, CMD
    CMP A, #$01
    BEQ DO_NOTE_ON
    CMP A, #$02
    BEQ DO_NOTE_OFF
    CMP A, #$03
    BEQ DO_SET_VOL
    CMP A, #$FF
    BEQ DO_RESET
    BRA MAIN_LOOP

DO_NOTE_ON:
    ; Set pitch and key-on for voice CH
    MOV A, CH
    ; voice register base = CH * $10
    ; (simplified: use lookup table for base address)
    MOV A, DATA_L
    ; write to DSP pitch low
    ; TODO: compute voice base and write to DSP_PITCH_L, DSP_PITCH_H, then KON
    BRA MAIN_LOOP

DO_NOTE_OFF:
    MOV A, CH
    ; key-off voice CH — set KOFF bit
    BRA MAIN_LOOP

DO_SET_VOL:
    ; Set voice volume
    BRA MAIN_LOOP

DO_RESET:
    ; Key off all voices
    MOV $F2, #DSP_KOFF
    MOV $F3, #$FF
    BRA MAIN_LOOP
"""


def convert_audio(workspace: Path, skip_llm: bool = False):
    audio_dir = workspace / "audio" / "brr_samples"
    audio_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads((workspace / "rom_manifest.json").read_text())

    print("[convert_audio] Synthesizing BRR samples ...")

    # Pulse waves (4 duty cycles)
    for duty, name in [(0.125, "sq_pulse_12"), (0.25, "sq_pulse_25"),
                       (0.50, "sq_pulse_50"), (0.75, "sq_pulse_75")]:
        brr = generate_pulse_brr(duty)
        out = audio_dir / f"{name}.brr"
        out.write_bytes(brr)
        print(f"[convert_audio]   {out.name}: {len(brr)} bytes")

    # Triangle
    tri_brr = generate_triangle_brr()
    (audio_dir / "triangle.brr").write_bytes(tri_brr)
    print(f"[convert_audio]   triangle.brr: {len(tri_brr)} bytes")

    # Silence (used as placeholder for noise/DMC when not available)
    silence = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00"  # single silent BRR block, end flag
    (audio_dir / "silence.brr").write_bytes(silence)

    # DMC: attempt to extract raw PCM from PRG-ROM
    prg_path = workspace / "prg_rom.bin"
    if prg_path.exists() and np is not None:
        prg_data = prg_path.read_bytes()
        # Heuristic: DMC samples in many games start in the last few PRG banks
        # without full music engine identification, we extract a 1KB window at $C000 offset
        dmc_offset = max(0, len(prg_data) - 0x1000)
        dmc_samples = decode_dmc_pcm(prg_data, dmc_offset, 256)
        if len(dmc_samples) > 0:
            dmc_brr = pcm_to_brr(dmc_samples / max(abs(dmc_samples).max(), 1e-6), loop=False)
            (audio_dir / "dmc.brr").write_bytes(dmc_brr)
            print(f"[convert_audio]   dmc.brr: {len(dmc_brr)} bytes")

    # Music engine identification via LLM
    if not skip_llm:
        print("[convert_audio] Identifying music engine via Claude ...")
        engine_info = identify_music_engine(workspace, manifest)
        (workspace / "audio" / "music_engine.json").write_text(json.dumps(engine_info, indent=2))
        if engine_info.get("identified"):
            print(f"[convert_audio] Music engine identified: {engine_info.get('notes', '')}")
        else:
            print(f"[convert_audio] Music engine not identified: {engine_info.get('reason', '')}")

    # Write SPC700 driver
    driver_path = workspace / "audio" / "spc_driver.asm"
    driver_path.write_text(SPC_DRIVER_ASM)
    print(f"[convert_audio] SPC700 driver written: {driver_path}")


def main():
    parser = argparse.ArgumentParser(description="Convert NES APU audio to SNES SPC700 BRR format")
    parser.add_argument("--workspace", default="workspace")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM music engine identification")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    if not (workspace / "rom_manifest.json").exists():
        print("ERROR: rom_manifest.json not found — run parse_rom.py first", file=sys.stderr)
        sys.exit(1)

    if np is None:
        print("[convert_audio] WARNING: numpy not installed — BRR synthesis will produce silent stubs",
              file=sys.stderr)

    convert_audio(workspace, skip_llm=args.no_llm)


if __name__ == "__main__":
    main()
