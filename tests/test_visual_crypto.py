from pathlib import Path

import pytest

from pwmanager.shamir import Share, format_share_token
from pwmanager.visual_crypto import combine_visual_shares, create_visual_recovery_share


RECOVERY_SHARE = (
    '{"scheme":"SSS-P521","threshold":2,"label":"recovery","x":3,'
    '"y":"0x2195f8064b743601f5e74f03cc608e645da28c590278cc0ddd2f4d2fdcb1e138c96df154f3171895b122bbfbf160af3665eaa51d01ebdc7b759f08bdc93e2b041d"}'
)


def test_visual_crypto_generates_reconstructable_qr(tmp_path: Path):
    result = create_visual_recovery_share(RECOVERY_SHARE, tmp_path, subpixel_size=4, qr_scale=8)
    assert result.qr.exists()
    assert result.share_1.exists()
    assert result.share_2.exists()
    assert result.overlay.exists()
    assert result.combined_qr.exists()

    recombined = combine_visual_shares(
        result.share_1,
        result.share_2,
        tmp_path / "manual_overlay.png",
        tmp_path / "manual_qr.png",
        subpixel_size=4,
        qr_scale=8,
    )
    assert Path(recombined["overlay"]).exists()
    assert Path(recombined["combined_qr"]).exists()


def test_combined_qr_decodes_to_recovery_share(tmp_path: Path):
    cv2 = pytest.importorskip("cv2")

    result = create_visual_recovery_share(RECOVERY_SHARE, tmp_path, subpixel_size=4, qr_scale=10)
    image = cv2.imread(str(result.combined_qr))
    decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    assert decoded == RECOVERY_SHARE


def test_visual_split_accepts_token_and_encodes_recovery_json(tmp_path: Path):
    cv2 = pytest.importorskip("cv2")
    token = format_share_token(
        Share(
            3,
            int(
                "2195f8064b743601f5e74f03cc608e645da28c590278cc0ddd2f4d2fdcb1e138c96df154f3171895b122bbfbf160af3665eaa51d01ebdc7b759f08bdc93e2b041d",
                16,
            ),
        ),
        "recovery",
    )

    result = create_visual_recovery_share(token, tmp_path, subpixel_size=4, qr_scale=10)
    image = cv2.imread(str(result.combined_qr))
    decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    assert decoded == RECOVERY_SHARE
