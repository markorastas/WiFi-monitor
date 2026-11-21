"""Generate a multi-resolution Windows .ico file matching the WiFi Monitor tray icon."""

from pathlib import Path
from PIL import Image, ImageDraw


def draw_icon(size: int = 256) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    accent = (46, 204, 113, 255)

    pad = max(2, size // 32)
    border = max(2, size // 20)
    draw.ellipse(
        (pad, pad, size - pad, size - pad),
        fill=(28, 32, 38, 255),
        outline=accent,
        width=border,
    )

    arc_w = max(2, size // 16)
    draw.arc(
        (int(size * 0.19), int(size * 0.25), int(size * 0.81), int(size * 0.87)),
        start=225,
        end=315,
        fill=accent,
        width=arc_w,
    )
    draw.arc(
        (int(size * 0.31), int(size * 0.37), int(size * 0.69), int(size * 0.75)),
        start=225,
        end=315,
        fill=accent,
        width=arc_w,
    )
    dot_r = max(2, int(size * 0.065))
    cx = size // 2
    cy = int(size * 0.69)
    draw.ellipse((cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r), fill=accent)
    return img


def main() -> None:
    out_path = Path(__file__).resolve().parent.parent / "build" / "wifi_monitor.ico"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    base = draw_icon(256)
    base.save(
        out_path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print(f"Generated icon: {out_path}")


if __name__ == "__main__":
    main()
