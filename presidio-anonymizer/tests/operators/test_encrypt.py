from unittest import mock
import pytest

from presidio_anonymizer.operators.encrypt import Encrypt
from presidio_anonymizer.operators import OperatorType
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators.aes_cipher import AESCipher


# --- operate() behavior ------------------------------------------------------

@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})
    assert anonymized_text == expected_anonymized_text

    # ensure AESCipher.encrypt was called with bytes key (str -> utf8)
    called_key, called_text = mock_encrypt.call_args[0]
    assert isinstance(called_key, (bytes, bytearray))
    assert called_text == "text"


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(mock_encrypt):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": b"1111111111111111"})
    assert anonymized_text == expected_anonymized_text

    # ensure bytes key was passed through unchanged
    called_key, called_text = mock_encrypt.call_args[0]
    assert called_key == b"1111111111111111"
    assert called_text == "text"


# --- validate() happy-path ---------------------------------------------------

def test_given_verifying_a_valid_length_key_no_exceptions_raised():
    # 16-char string -> 128-bit
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_a_valid_length_bytes_key_no_exceptions_raised():
    # 16 bytes -> 128-bit
    Encrypt().validate(params={"key": b"1111111111111111"})


# --- validate() error paths --------------------------------------------------

def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    # Short string -> invalid size, should raise without mocks
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})


def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised():
    # The provided bytes value is actually valid (16 bytes).
    # Force validate() to treat it as invalid by mocking the size check.
    with mock.patch.object(AESCipher, "is_valid_key_size", return_value=False):
        with pytest.raises(
            InvalidParamError,
            match="Invalid input, key must be of length 128, 192 or 256 bits",
        ):
            Encrypt().validate(params={"key": b"1111111111111111"})


# --- small coverage: name/type ----------------------------------------------

def test_operator_name():
    assert Encrypt().operator_name() == "encrypt"


def test_operator_type():
    assert Encrypt().operator_type() == OperatorType.Anonymize


# --- black-box: valid key sizes ---------------------------------------------

@pytest.mark.parametrize(
    "key",
    [
        "1" * 16,   # 128-bit string
        "1" * 24,   # 192-bit string
        "1" * 32,   # 256-bit string
        b"1" * 16,  # 128-bit bytes
        b"1" * 24,  # 192-bit bytes
        b"1" * 32,  # 256-bit bytes
    ],
)
def test_valid_keys(key):
    # Should not raise for any valid key size
    Encrypt().validate({"key": key})


import pytest
from presidio_anonymizer.operators.encrypt import Encrypt

@pytest.mark.parametrize(
    "key",
    [
        "1" * 16,   # 128-bit string
        "1" * 24,   # 192-bit string
        "1" * 32,   # 256-bit string
        b"1" * 16,  # 128-bit bytes
        b"1" * 24,  # 192-bit bytes
        b"1" * 32,  # 256-bit bytes
    ],
)
def test_valid_keys(key):
    # validate() should NOT raise for any valid key size
    Encrypt().validate({"key": key})
