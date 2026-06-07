from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

import qrcode
from PIL import Image, ImageDraw

from .shamir import format_share, parse_share


BLACK = 0
WHITE = 255

PATTERNS = (
    (1, 1, 0, 0),
    (1, 0, 1, 0),
    (1, 0, 0, 1),
    (0, 1, 1, 0),
    (0, 1, 0, 1),
    (0, 0, 1, 1),
)


@dataclass(frozen=True)
class VisualCryptoResult:
    qr: Path
    share_1: Path
    share_2: Path
    overlay: Path
    combined_qr: Path
    matrix_size: int

    def to_json(self) -> dict:
        return {
            "qr": str(self.qr),
            "share_1": str(self.share_1),
            "share_2": str(self.share_2),
            "overlay": str(self.overlay),
            "combined_qr": str(self.combined_qr),
            "matrix_size": self.matrix_size,
        }


def _complement(pattern: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    return tuple(1 - bit for bit in pattern)  # type: ignore[return-value]


def _make_qr_matrix(payload: str) -> list[list[bool]]:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.get_matrix()


def _render_qr_matrix(matrix: list[list[bool]], path: Path, scale: int) -> None:
    size = len(matrix)
    image = Image.new("L", (size * scale, size * scale), WHITE)
    draw = ImageDraw.Draw(image)
    for row, values in enumerate(matrix):
        for col, is_black in enumerate(values):
            if is_black:
                x0 = col * scale
                y0 = row * scale
                draw.rectangle((x0, y0, x0 + scale - 1, y0 + scale - 1), fill=BLACK)
    image.save(path)


def _draw_pattern(draw: ImageDraw.ImageDraw, col: int, row: int, pattern: tuple[int, ...], subpixel_size: int) -> None:
    x_base = col * 2 * subpixel_size
    y_base = row * 2 * subpixel_size
    for idx, bit in enumerate(pattern):
        if not bit:
            continue
        x = x_base + (idx % 2) * subpixel_size
        y = y_base + (idx // 2) * subpixel_size
        draw.rectangle((x, y, x + subpixel_size - 1, y + subpixel_size - 1), fill=BLACK)


def _render_visual_shares(
    matrix: list[list[bool]],
    share_1_path: Path,
    share_2_path: Path,
    subpixel_size: int,
) -> None:
    size = len(matrix)
    image_size = size * 2 * subpixel_size
    share_1 = Image.new("L", (image_size, image_size), WHITE)
    share_2 = Image.new("L", (image_size, image_size), WHITE)
    draw_1 = ImageDraw.Draw(share_1)
    draw_2 = ImageDraw.Draw(share_2)

    for row, values in enumerate(matrix):
        for col, is_black in enumerate(values):
            pattern_1 = secrets.choice(PATTERNS)
            pattern_2 = _complement(pattern_1) if is_black else pattern_1
            _draw_pattern(draw_1, col, row, pattern_1, subpixel_size)
            _draw_pattern(draw_2, col, row, pattern_2, subpixel_size)

    share_1.save(share_1_path)
    share_2.save(share_2_path)


def _is_black(value: int) -> bool:
    return value < 128


def _overlay_images(share_1_path: Path, share_2_path: Path) -> Image.Image:
    share_1 = Image.open(share_1_path).convert("L")
    share_2 = Image.open(share_2_path).convert("L")
    if share_1.size != share_2.size:
        raise ValueError("visual shares must have the same size")

    overlay = Image.new("L", share_1.size, WHITE)
    pixels_1 = share_1.load()
    pixels_2 = share_2.load()
    pixels_o = overlay.load()
    width, height = share_1.size
    for y in range(height):
        for x in range(width):
            pixels_o[x, y] = BLACK if _is_black(pixels_1[x, y]) or _is_black(pixels_2[x, y]) else WHITE
    return overlay


def _subpixel_is_black(overlay: Image.Image, x0: int, y0: int, subpixel_size: int) -> bool:
    pixels = overlay.load()
    black = 0
    total = subpixel_size * subpixel_size
    for y in range(y0, y0 + subpixel_size):
        for x in range(x0, x0 + subpixel_size):
            if _is_black(pixels[x, y]):
                black += 1
    return black >= total // 2


def _collapse_overlay_to_matrix(overlay: Image.Image, subpixel_size: int) -> list[list[bool]]:
    if subpixel_size < 1:
        raise ValueError("subpixel size must be at least 1")
    width, height = overlay.size
    block_size = 2 * subpixel_size
    if width != height or width % block_size != 0:
        raise ValueError("visual share size is not compatible with the selected subpixel size")

    matrix_size = width // block_size
    matrix: list[list[bool]] = []
    for row in range(matrix_size):
        values: list[bool] = []
        for col in range(matrix_size):
            x_base = col * block_size
            y_base = row * block_size
            black_subpixels = 0
            for sy in range(2):
                for sx in range(2):
                    if _subpixel_is_black(overlay, x_base + sx * subpixel_size, y_base + sy * subpixel_size, subpixel_size):
                        black_subpixels += 1
            values.append(black_subpixels >= 3)
        matrix.append(values)
    return matrix


def create_visual_recovery_share(
    recovery_share_text: str,
    out_dir: Path,
    prefix: str = "recovery_share",
    subpixel_size: int = 8,
    qr_scale: int = 10,
) -> VisualCryptoResult:
    """Create a QR (2,2)."""
    recovery_share = parse_share(recovery_share_text)
    payload = format_share(recovery_share, "recovery")
    if subpixel_size < 2:
        raise ValueError("subpixel size must be at least 2")
    if qr_scale < 2:
        raise ValueError("QR scale must be at least 2")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix = _make_qr_matrix(payload)
    qr_path = out_dir / f"{prefix}_qr.png"
    share_1_path = out_dir / f"{prefix}_visual_share_1.png"
    share_2_path = out_dir / f"{prefix}_visual_share_2.png"
    overlay_path = out_dir / f"{prefix}_combined_overlay.png"
    combined_qr_path = out_dir / f"{prefix}_combined_qr.png"

    _render_qr_matrix(matrix, qr_path, qr_scale)
    _render_visual_shares(matrix, share_1_path, share_2_path, subpixel_size)
    combine_visual_shares(share_1_path, share_2_path, overlay_path, combined_qr_path, subpixel_size, qr_scale)

    return VisualCryptoResult(
        qr=qr_path,
        share_1=share_1_path,
        share_2=share_2_path,
        overlay=overlay_path,
        combined_qr=combined_qr_path,
        matrix_size=len(matrix),
    )


def combine_visual_shares(
    share_1_path: Path,
    share_2_path: Path,
    overlay_path: Path,
    combined_qr_path: Path,
    subpixel_size: int = 8,
    qr_scale: int = 10,
) -> dict:
    """Penggabungan QR untuk direkonstruksi."""
    overlay = _overlay_images(Path(share_1_path), Path(share_2_path))
    overlay_path = Path(overlay_path)
    combined_qr_path = Path(combined_qr_path)
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    combined_qr_path.parent.mkdir(parents=True, exist_ok=True)

    overlay.save(overlay_path)
    matrix = _collapse_overlay_to_matrix(overlay, subpixel_size)
    _render_qr_matrix(matrix, combined_qr_path, qr_scale)
    return {
        "overlay": str(overlay_path),
        "combined_qr": str(combined_qr_path),
        "matrix_size": len(matrix),
    }
