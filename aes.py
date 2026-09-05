from Crypto.Cipher import AES

from round_key import RoundKey, TOTAL_ROUND
from state_box import StateBox


BLOCK_BITS = 128
BLOCK_MASK = (1 << BLOCK_BITS) - 1


def _validate_block(value: int, name: str) -> None:
    """Validate an unsigned 128-bit integer."""
    if not isinstance(value, int) or not 0 <= value <= BLOCK_MASK:
        raise ValueError(f"{name} must be an unsigned 128-bit integer")


def encrypt(key: int, plaintext: int) -> int:
    """Encrypt one 128-bit block with AES-128."""
    _validate_block(key, "key")
    _validate_block(plaintext, "plaintext")

    round_keys = RoundKey()
    round_keys.key_schedule(key)
    state = StateBox(plaintext)
    state.add_round_key(round_keys.get_round_key(0))

    for round_index in range(1, TOTAL_ROUND + 1):
        state.sub_bytes()
        state.shift_rows()
        if round_index < TOTAL_ROUND:
            state.mix_columns()
        state.add_round_key(round_keys.get_round_key(round_index))

    return state.to_int()


def decrypt(key: int, ciphertext: int) -> int:
    """Decrypt one 128-bit block with AES-128."""
    _validate_block(key, "key")
    _validate_block(ciphertext, "ciphertext")

    round_keys = RoundKey()
    round_keys.key_schedule(key)
    state = StateBox(ciphertext)
    state.add_round_key(round_keys.get_round_key(TOTAL_ROUND))

    for round_index in range(TOTAL_ROUND - 1, -1, -1):
        state.inv_shift_rows()
        state.inv_sub_bytes()
        state.add_round_key(round_keys.get_round_key(round_index))
        if round_index > 0:
            state.inv_mix_columns()

    return state.to_int()


def aes_reference(key: int, plaintext: int) -> int:
    """Encrypt one block with PyCryptodome for implementation verification."""
    _validate_block(key, "key")
    _validate_block(plaintext, "plaintext")

    key_bytes = key.to_bytes(16, byteorder="big")
    plaintext_bytes = plaintext.to_bytes(16, byteorder="big")
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext_bytes = cipher.encrypt(plaintext_bytes)
    return int.from_bytes(ciphertext_bytes, byteorder="big")
