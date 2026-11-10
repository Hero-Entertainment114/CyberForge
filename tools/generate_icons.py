#!/usr/bin/env python3
"""Generate CyberForge desktop icons in PNG, ICO and ICNS formats."""
from __future__ import annotations
import struct
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
SIZE = 1024


def create_master() -> Image.Image:
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    px = image.load()
    for y in range(SIZE):
        for x in range(SIZE):
            t = (x + y) / (2 * SIZE)
            px[x, y] = (int(10 + 8*t), int(22 + 24*t), int(40 + 35*t), 255)

    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).rounded_rectangle((36, 36, 988, 988), radius=220, fill=255)
    image.putalpha(mask)

    # Soft cyan edge and an inset shield.
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((38, 38, 986, 986), radius=218, outline=(64, 206, 224, 245), width=18)
    shield = [(512, 150), (806, 292), (784, 680), (512, 876), (240, 680), (218, 292)]
    draw.polygon(shield, fill=(13, 36, 58, 255), outline=(61, 164, 191, 255))
    draw.line(shield + [shield[0]], fill=(89, 223, 232, 235), width=16, joint="curve")

    # The open C arc suggests CyberForge; horizontal traces turn it into a circuit mark.
    draw.arc((330, 318, 690, 678), start=42, end=318, fill=(120, 239, 232, 255), width=82)
    draw.line((300, 403, 430, 403), fill=(120, 239, 232, 255), width=44)
    draw.line((300, 593, 430, 593), fill=(120, 239, 232, 255), width=44)
    draw.ellipse((264, 375, 332, 443), fill=(255, 174, 92, 255))
    draw.ellipse((264, 559, 332, 627), fill=(255, 174, 92, 255))

    # Small forge spark over the open end of the C.
    spark = [(710, 286), (740, 366), (820, 396), (740, 426), (710, 508), (680, 426), (600, 396), (680, 366)]
    draw.polygon(spark, fill=(255, 188, 105, 255))
    return image


def write_icns(master: Image.Image, output: Path) -> None:
    chunks = []
    for size, code in [(16, "icp4"), (32, "icp5"), (64, "icp6"), (128, "ic07"), (256, "ic08"), (512, "ic09"), (1024, "ic10")]:
        buf = output.parent / f".icon-{size}.png"
        master.resize((size, size), Image.Resampling.LANCZOS).save(buf, format="PNG", optimize=True)
        data = buf.read_bytes()
        buf.unlink()
        chunks.append(code.encode("ascii") + struct.pack(">I", len(data) + 8) + data)
    payload = b"".join(chunks)
    output.write_bytes(b"icns" + struct.pack(">I", len(payload) + 8) + payload)


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    master = create_master()
    master.save(ASSETS / "cyberforge.png", optimize=True)
    master.save(ASSETS / "cyberforge.ico", format="ICO", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
    write_icns(master, ASSETS / "cyberforge.icns")
    print("Generated assets/cyberforge.png, .ico and .icns")


if __name__ == "__main__":
    main()
