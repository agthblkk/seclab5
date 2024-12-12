import pytest
from src.main import generate_keys, encrypt_message, decrypt_message

@pytest.fixture(scope="module")
def keys():
    public_key, private_key = generate_keys()
    return public_key, private_key

def test_encryption_decryption_ascii(keys):
    public_key, private_key = keys
    original_message = "Hello, world!"
    encrypted = encrypt_message(original_message, public_key)
    decrypted = decrypt_message(encrypted, private_key)
    assert original_message == decrypted

def test_encryption_decryption_empty_string(keys):
    public_key, private_key = keys
    original_message = ""
    encrypted = encrypt_message(original_message, public_key)
    decrypted = decrypt_message(encrypted, private_key)
    assert original_message == decrypted

def test_encryption_decryption_unicode(keys):
    public_key, private_key = keys
    original_message = "Привіт, світ!"
    encrypted = encrypt_message(original_message, public_key)
    decrypted = decrypt_message(encrypted, private_key)
    assert original_message == decrypted

def test_encryption_decryption_long_message(keys):
    public_key, private_key = keys
    original_message = "A" * 50 + "Б" * 50 + 10
    encrypted = encrypt_message(original_message, public_key)
    decrypted = decrypt_message(encrypted, private_key)
    assert original_message == decrypted

def test_encryption_without_public_key(keys):
    with pytest.raises(ValueError):
        encrypt_message("Message", None)

def test_decryption_with_invalid_private_key(keys):
    public_key, private_key = keys
    wrong_private_key = ([], 1, 1, 1)
    original_message = "Test"
    encrypted = encrypt_message(original_message, public_key)
    with pytest.raises(ValueError):
        decrypt_message(encrypted, wrong_private_key)
