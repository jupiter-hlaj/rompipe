#!/usr/bin/env python3
"""
Stage 6: convert_graphics.py
Converts NES CHR-ROM (2bpp planar) to SNES 4bpp planar tile format.
Converts NES palette indices to SNES 15-bit BGR CGRAM data.
Optionally upscales tiles via ComfyUI (--upscale flag).

Output:
  workspace/tiles/tile_NNNN_nes.png    — original NES tiles as PNG
  workspace/chr_snes.bin               — SNES 4bpp tile data for VRAM load
  workspace/palette_snes.bin           — SNES 15-bit BGR palette for CGRAM load
  workspace/tile_map.json              — NES tile index → SNES tile index + palette
"""
import argparse
import json
import struct
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    Image = None

# NES master palette: 64 RGB triples (NTSC canonical)
NES_PALETTE_RGB = [
    (84,84,84),   (0,30,116),   (8,16,144),   (48,0,136),
    (68,0,100),   (92,0,48),    (84,4,0),     (60,24,0),
    (32,42,0),    (8,58,0),     (0,64,0),     (0,60,0),
    (0,50,60),    (0,0,0),      (0,0,0),      (0,0,0),
    (152,150,152),(8,76,196),   (48,50,236),  (92,30,228),
    (136,20,176), (160,20,100), (152,34,32),  (120,60,0),
    (84,90,0),    (40,114,0),   (8,124,0),    (0,118,40),
    (0,102,120),  (0,0,0),      (0,0,0),      (0,0,0),
    (236,238,236),(76,154,236), (120,124,236),(176,98,236),
    (228,84,236), (236,88,180), (236,106,100),(212,136,32),
    (160,170,0),  (116,196,0),  (76,208,32),  (56,204,108),
    (56,180,204), (60,60,60),   (0,0,0),      (0,0,0),
    (236,238,236),(168,204,236),(188,188,236),(212,178,236),
    (236,174,236),(236,174,212),(236,180,176),(228,196,144),
    (204,210,120),(180,222,120),(168,226,144),(152,226,180),
    (160,214,228),(160,162,160),(0,0,0),      (0,0,0),
]


def rgb_to_snes_bgr(r: int, g: int, b: int) -> int:
    """Convert 8-bit RGB to SNES 15-bit BGR word."""
    return ((b >> 3) << 10) | ((g >> 3) << 5) | (r >> 3)


def nes_tile_to_snes_4bpp(tile_bytes: bytes) -> bytes:
    """
    Convert one NES tile (16 bytes, 2bpp planar) to SNES 4bpp planar (32 bytes).
    NES format: 8 bytes plane0 (LSB) + 8 bytes plane1 (MSB)
    SNES format: interleaved pairs (plane0_row, plane1_row) × 8 rows,
                 then (plane2_row=0, plane3_row=0) × 8 rows
    """
    if len(tile_bytes) != 16:
        raise ValueError(f"Expected 16-byte NES tile, got {len(tile_bytes)}")
    plane0 = tile_bytes[0:8]
    plane1 = tile_bytes[8:16]

    snes_planes_01 = bytearray()
    for row in range(8):
        snes_planes_01.append(plane0[row])
        snes_planes_01.append(plane1[row])

    # Planes 2 & 3 are zero (NES has 2bpp; SNES tile colors 0–3 of 16-color palette)
    snes_planes_23 = bytes(16)

    return bytes(snes_planes_01) + snes_planes_23


def tile_to_rgba_image(tile_bytes: bytes, palette_rgb: list) -> "Image":
    """Render a 2bpp NES tile to an 8×8 RGBA PIL image using the given 4-color palette."""
    if Image is None:
        return None
    plane0 = tile_bytes[0:8]
    plane1 = tile_bytes[8:16]
    img = Image.new("RGBA", (8, 8))
    pixels = []
    for row in range(8):
        for col in range(7, -1, -1):
            bit0 = (plane0[row] >> col) & 1
            bit1 = (plane1[row] >> col) & 1
            color_idx = (bit1 << 1) | bit0
            r, g, b = palette_rgb[color_idx]
            pixels.append((r, g, b, 255))
    img.putdata(pixels)
    return img


def default_nes_subpalette() -> list:
    """Return a default 4-color NES sub-palette (greyscale ramp)."""
    return [NES_PALETTE_RGB[0x0F], NES_PALETTE_RGB[0x00],
            NES_PALETTE_RGB[0x10], NES_PALETTE_RGB[0x30]]


def convert_graphics(workspace: Path, upscale: bool = False):
    chr_bin = workspace / "chr_rom.bin"
    if not chr_bin.exists() or chr_bin.stat().st_size == 0:
        print("[convert_graphics] No CHR-ROM data (CHR-RAM game or missing) — skipping tile conversion")
        (workspace / "chr_snes.bin").write_bytes(b"")
        (workspace / "palette_snes.bin").write_bytes(b"")
        (workspace / "tile_map.json").write_text("[]")
        return

    chr_data  = chr_bin.read_bytes()
    tile_count = len(chr_data) // 16
    print(f"[convert_graphics] Converting {tile_count} tiles ...")

    tiles_dir = workspace / "tiles"
    tiles_dir.mkdir(parents=True, exist_ok=True)

    snes_chr  = bytearray()
    tile_map  = []
    default_pal = default_nes_subpalette()

    for i in range(tile_count):
        tile_bytes = chr_data[i * 16: (i + 1) * 16]

        # Convert to SNES 4bpp
        snes_tile = nes_tile_to_snes_4bpp(tile_bytes)
        snes_chr.extend(snes_tile)

        # Export PNG for visual reference (and optional ComfyUI upscale)
        if Image is not None:
            img = tile_to_rgba_image(tile_bytes, default_pal)
            if img:
                img.save(tiles_dir / f"tile_{i:04d}_nes.png")

        tile_map.append({"nes_tile": i, "snes_tile": i, "palette": 0})

    chr_snes_path = workspace / "chr_snes.bin"
    chr_snes_path.write_bytes(bytes(snes_chr))
    print(f"[convert_graphics] CHR SNES: {len(snes_chr)} bytes → {chr_snes_path}")

    # Generate SNES CGRAM palette data
    # Each NES sub-palette (4 colors) → 4 × 2-byte SNES color words
    # We generate one 16-color SNES palette (4 NES sub-palettes × 4 colors)
    cgram = bytearray()
    for color_idx in range(16):
        nes_rgb = NES_PALETTE_RGB[color_idx % len(NES_PALETTE_RGB)]
        snes_color = rgb_to_snes_bgr(*nes_rgb)
        cgram.extend(struct.pack("<H", snes_color))

    pal_path = workspace / "palette_snes.bin"
    pal_path.write_bytes(bytes(cgram))
    print(f"[convert_graphics] Palette: {len(cgram)} bytes → {pal_path}")

    (workspace / "tile_map.json").write_text(json.dumps(tile_map, indent=2))

    if upscale:
        print("[convert_graphics] --upscale requested: piping tiles through ComfyUI ...")
        _run_comfyui_upscale(tiles_dir)


def _run_comfyui_upscale(tiles_dir: Path):
    """
    Optional: send NES tile PNGs to ComfyUI for AI upscaling.
    Requires ComfyUI running at http://127.0.0.1:8188
    Upscaled images are saved as tile_NNNN_hd.png for reference.
    """
    import urllib.request
    import urllib.error

    try:
        urllib.request.urlopen("http://127.0.0.1:8188/system_stats", timeout=3)
    except (urllib.error.URLError, OSError):
        print("[convert_graphics] WARNING: ComfyUI not running at port 8188 — skipping upscale",
              file=sys.stderr)
        return

    # Import comfy_client logic if available
    comfy_client_path = Path(__file__).parent / "comfy_client.py"
    if comfy_client_path.exists():
        import importlib.util
        spec = importlib.util.spec_from_file_location("comfy_client", comfy_client_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "upscale_directory"):
            mod.upscale_directory(tiles_dir, tiles_dir, suffix="_hd")
            return

    print("[convert_graphics] comfy_client.py not found — skipping upscale", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Convert NES CHR-ROM to SNES 4bpp format")
    parser.add_argument("--workspace", default="workspace")
    parser.add_argument("--upscale", action="store_true",
                        help="Optionally upscale tiles via ComfyUI (requires server on port 8188)")
    args = parser.parse_args()

    workspace = Path(args.workspace)
    if not (workspace / "rom_manifest.json").exists():
        print("ERROR: rom_manifest.json not found — run parse_rom.py first", file=sys.stderr)
        sys.exit(1)

    convert_graphics(workspace, upscale=args.upscale)


if __name__ == "__main__":
    main()
