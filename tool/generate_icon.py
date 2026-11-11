#!/usr/bin/env python3
"""Generate a fresh 'lib' wordmark app icon (no system fonts required)."""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "assets" / "icon"
APPICONSET = OUT_DIR / "AppIcon.appiconset"
MASTER = OUT_DIR / "app_icon.png"

# iOS AppIcon slots used by a Flutter-created Runner.
IOS_SLOTS = [
    ("Icon-App-20x20@2x.png", 40),
    ("Icon-App-20x20@3x.png", 60),
    ("Icon-App-29x29@2x.png", 58),
    ("Icon-App-29x29@3x.png", 87),
    ("Icon-App-40x40@2x.png", 80),
    ("Icon-App-40x40@3x.png", 120),
    ("Icon-App-60x60@2x.png", 120),
    ("Icon-App-60x60@3x.png", 180),
    ("Icon-App-76x76@1x.png", 76),
    ("Icon-App-76x76@2x.png", 152),
    ("Icon-App-83.5x83.5@2x.png", 167),
    ("Icon-App-1024x1024@1x.png", 1024),
]

CONTENTS = {
    "images": [
        {"idiom": "iphone", "scale": "2x", "size": "20x20", "filename": "Icon-App-20x20@2x.png"},
        {"idiom": "iphone", "scale": "3x", "size": "20x20", "filename": "Icon-App-20x20@3x.png"},
        {"idiom": "iphone", "scale": "2x", "size": "29x29", "filename": "Icon-App-29x29@2x.png"},
        {"idiom": "iphone", "scale": "3x", "size": "29x29", "filename": "Icon-App-29x29@3x.png"},
        {"idiom": "iphone", "scale": "2x", "size": "40x40", "filename": "Icon-App-40x40@2x.png"},
        {"idiom": "iphone", "scale": "3x", "size": "40x40", "filename": "Icon-App-40x40@3x.png"},
        {"idiom": "iphone", "scale": "2x", "size": "60x60", "filename": "Icon-App-60x60@2x.png"},
        {"idiom": "iphone", "scale": "3x", "size": "60x60", "filename": "Icon-App-60x60@3x.png"},
        {"idiom": "ipad", "scale": "1x", "size": "76x76", "filename": "Icon-App-76x76@1x.png"},
        {"idiom": "ipad", "scale": "2x", "size": "76x76", "filename": "Icon-App-76x76@2x.png"},
        {"idiom": "ipad", "scale": "2x", "size": "83.5x83.5", "filename": "Icon-App-83.5x83.5@2x.png"},
        {"idiom": "ios-marketing", "scale": "1x", "size": "1024x1024", "filename": "Icon-App-1024x1024@1x.png"},
    ],
    "info": {"author": "xcode", "version": 1},
}


def lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))  # type: ignore[return-value]


def gradient(size: int) -> Image.Image:
    img = Image.new("RGB", (size, size))
    px = img.load()
    top = (214, 240, 232)
    bottom = (196, 222, 245)
    for y in range(size):
        ty = y / (size - 1)
        for x in range(size):
            tx = x / (size - 1)
            t = 0.55 * ty + 0.45 * tx
            px[x, y] = lerp(top, bottom, t)
    return img.convert("RGBA")


def rounded_rect(
    draw: ImageDraw.ImageDraw,
    box: tuple[float, float, float, float],
    radius: float,
    fill,
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def letter_l(draw: ImageDraw.ImageDraw, x: float, y: float, h: float, w: float, color) -> float:
    r = w / 2
    rounded_rect(draw, (x, y, x + w, y + h), r, color)
    return w


def letter_i(draw: ImageDraw.ImageDraw, x: float, y: float, h: float, w: float, color) -> float:
    r = w / 2
    gap = w * 0.55
    dot = w * 1.05
    draw.ellipse((x + (w - dot) / 2, y, x + (w + dot) / 2, y + dot), fill=color)
    stem_top = y + dot + gap
    rounded_rect(draw, (x, stem_top, x + w, y + h), r, color)
    return w


def letter_b(draw: ImageDraw.ImageDraw, x: float, y: float, h: float, w: float, color, bg) -> float:
    r = w / 2
    bowl_d = h * 0.62
    bowl_x = x + w * 0.38
    bowl_y = y + h - bowl_d
    draw.ellipse((bowl_x, bowl_y, bowl_x + bowl_d, bowl_y + bowl_d), fill=color)
    inner = bowl_d * 0.42
    cx = bowl_x + bowl_d / 2
    cy = bowl_y + bowl_d / 2
    draw.ellipse((cx - inner / 2, cy - inner / 2, cx + inner / 2, cy + inner / 2), fill=bg)
    rounded_rect(draw, (x, y, x + w, y + h), r, color)
    return bowl_x + bowl_d - x


def compose(size: int = 2048) -> Image.Image:
    base = gradient(size)
    overlay = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    pad = int(size * 0.14)
    card = (pad, pad, size - pad, size - pad)
    rounded_rect(draw, card, size * 0.22, (255, 255, 255, 168))

    blob = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bd = ImageDraw.Draw(blob)
    s = size * 0.55
    bd.ellipse((size * 0.28, size * 0.18, size * 0.28 + s, size * 0.18 + s), fill=(180, 230, 214, 90))
    blob = blob.filter(ImageFilter.GaussianBlur(size * 0.04))
    overlay = Image.alpha_composite(overlay, blob)
    draw = ImageDraw.Draw(overlay)

    h = size * 0.38
    w = size * 0.072
    gap = size * 0.055
    y = (size - h) / 2 + size * 0.01
    ink = (47, 112, 108, 255)
    ghost = (255, 255, 255, 90)

    def measure() -> float:
        return w + gap + w + gap + (w * 0.38 + h * 0.62)

    total = measure()
    x = (size - total) / 2

    def draw_word(d: ImageDraw.ImageDraw, ox: float, oy: float, color, cut) -> None:
        cx = ox
        cx += letter_l(d, cx, oy, h, w, color) + gap
        cx += letter_i(d, cx, oy, h, w, color) + gap
        letter_b(d, cx, oy, h, w, color, cut)

    shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_word(ImageDraw.Draw(shadow), x, y + size * 0.012, ghost, (255, 255, 255, 0))
    shadow = shadow.filter(ImageFilter.GaussianBlur(size * 0.008))
    overlay = Image.alpha_composite(overlay, shadow)
    draw = ImageDraw.Draw(overlay)
    draw_word(draw, x, y, ink, (255, 255, 255, 230))

    return Image.alpha_composite(base, overlay)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    APPICONSET.mkdir(parents=True, exist_ok=True)

    master = compose(2048).convert("RGB").resize((1024, 1024), Image.Resampling.LANCZOS)
    master.save(MASTER, "PNG")

    for name, px in IOS_SLOTS:
        im = master if px == 1024 else master.resize((px, px), Image.Resampling.LANCZOS)
        im.save(APPICONSET / name, "PNG")

    (APPICONSET / "Contents.json").write_text(json.dumps(CONTENTS, indent=2) + "\n")
    print(f"wrote {MASTER} and {len(IOS_SLOTS)} iOS slots")


if __name__ == "__main__":
    main()
