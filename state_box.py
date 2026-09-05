from aes_tables import AesTables
from round_key import WORD_SIZE


BYTE_MASK = 0xFF


class StateBox:
    """Represent and transform the AES 4x4 byte state matrix."""

    def __init__(self, plaintext: int) -> None:
        self._state = [[0 for _ in range(WORD_SIZE)] for _ in range(WORD_SIZE)]
        value = plaintext
        for column in range(WORD_SIZE - 1, -1, -1):
            for row in range(WORD_SIZE - 1, -1, -1):
                self._state[row][column] = value & BYTE_MASK
                value >>= 8

    def _sub_bytes(self, s_box: list[list[int]]) -> None:
        for row in range(WORD_SIZE):
            for column in range(WORD_SIZE):
                value = self._state[row][column] & BYTE_MASK
                self._state[row][column] = s_box[value >> 4][value & 0x0F]

    def sub_bytes(self) -> None:
        """Apply the AES S-box."""
        self._sub_bytes(AesTables.S_BOX)

    def inv_sub_bytes(self) -> None:
        """Apply the inverse AES S-box."""
        self._sub_bytes(AesTables.INV_S_BOX)

    def shift_rows(self) -> None:
        """Shift each state row cyclically to the left."""
        for row in range(1, WORD_SIZE):
            self._state[row] = self._state[row][row:] + self._state[row][:row]

    def inv_shift_rows(self) -> None:
        """Shift each state row cyclically to the right."""
        for row in range(1, WORD_SIZE):
            shift = WORD_SIZE - row
            self._state[row] = self._state[row][shift:] + self._state[row][:shift]

    @staticmethod
    def _galois_multiply(left: int, right: int) -> int:
        """Multiply two bytes in AES's GF(2^8)."""
        left &= BYTE_MASK
        right &= BYTE_MASK
        result = 0

        for _ in range(8):
            if right & 1:
                result ^= left
            high_bit = left & 0x80
            left = (left << 1) & BYTE_MASK
            if high_bit:
                left ^= 0x1B
            right >>= 1

        return result & BYTE_MASK

    def _mix_columns(self, matrix: list[list[int]]) -> None:
        mixed_state = [[0 for _ in range(WORD_SIZE)] for _ in range(WORD_SIZE)]
        for column in range(WORD_SIZE):
            for row in range(WORD_SIZE):
                for index in range(WORD_SIZE):
                    mixed_state[row][column] ^= self._galois_multiply(
                        matrix[row][index], self._state[index][column]
                    )
        self._state = mixed_state

    def mix_columns(self) -> None:
        """Apply the AES MixColumns transformation."""
        self._mix_columns(AesTables.MIX_COLUMNS_MATRIX)

    def inv_mix_columns(self) -> None:
        """Apply the inverse MixColumns transformation."""
        self._mix_columns(AesTables.INV_MIX_COLUMNS_MATRIX)

    def add_round_key(self, round_key: int) -> None:
        """XOR a 128-bit round key with the state."""
        for column in range(WORD_SIZE - 1, -1, -1):
            for row in range(WORD_SIZE - 1, -1, -1):
                self._state[row][column] ^= round_key & BYTE_MASK
                round_key >>= 8

    def to_int(self) -> int:
        """Convert the state matrix to a 128-bit integer."""
        result = 0
        for column in range(WORD_SIZE):
            for row in range(WORD_SIZE):
                result = (result << 8) | (self._state[row][column] & BYTE_MASK)
        return result
