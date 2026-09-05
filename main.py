from aes import aes_reference, decrypt, encrypt


def main() -> None:
    """Run the AES-128 implementation against a standard test vector."""
    key = 0x000102030405060708090A0B0C0D0E0F
    plaintext = 0x00112233445566778899AABBCCDDEEFF
    expected_ciphertext = 0x69C4E0D86A7B0430D8CDB78070B4C55A

    ciphertext = encrypt(key, plaintext)
    recovered_plaintext = decrypt(key, ciphertext)
    reference_ciphertext = aes_reference(key, plaintext)

    print(f"key                 = 0x{key:032x}")
    print(f"plaintext           = 0x{plaintext:032x}")
    print(f"ciphertext          = 0x{ciphertext:032x}")
    print(f"expected ciphertext = 0x{expected_ciphertext:032x}")
    print(f"reference ciphertext = 0x{reference_ciphertext:032x}")
    print(f"encryption passed   = {ciphertext == expected_ciphertext}")
    print(f"reference passed    = {ciphertext == reference_ciphertext}")
    print(f"decrypted plaintext = 0x{recovered_plaintext:032x}")
    print(f"decryption passed   = {recovered_plaintext == plaintext}")


if __name__ == "__main__":
    main()
