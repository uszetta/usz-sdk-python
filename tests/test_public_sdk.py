import pytest
import usz_sdk
from usz_sdk.card_offramp import ZeroPIIViolationError, validate_bin_sponsor, format_card_pos_receipt
from usz_sdk.point_delegation import assert_zero_pii_payload


def test_sdk_version():
    assert usz_sdk.__version__ == "0.0.5"


def test_zero_pii_guardrail():
    assert_zero_pii_payload({"wallet": "0x0000000000000000000000000000000000000001", "amount": "10.0"})
    with pytest.raises(ZeroPIIViolationError):
        assert_zero_pii_payload({"email": "user@example.com"})


def test_bin_sponsor_and_receipt():
    assert validate_bin_sponsor("kulipa") == "kulipa"
    receipt = format_card_pos_receipt(12_500_000_000_000_000_000, 87_500_000_000_000_000_000)
    assert "12.50" in receipt and "87.50" in receipt
