from aes_tables import AesTables


TOTAL_ROUND = 10
WORD_SIZE = 4


class RoundKey:
    """Generate and store the eleven AES-128 round keys."""

    def __init__(self) -> None:
        self._words = [
            [0 for _ in range(WORD_SIZE * (TOTAL_ROUND + 1))]
            for _ in range(WORD_SIZE)
        ]

    def _set_key(self, key: int) -> None:
        for column in range(WORD_SIZE - 1, -1, -1):
            for row in range(WORD_SIZE - 1, -1, -1):
                self._words[row][column] = key & 0xFF
                key >>= 8

    def _copy_word(self, column_index: int) -> list[list[int]]:
        return [[self._words[row][column_index]] for row in range(WORD_SIZE)]

    def _rot_word(self, word: list[list[int]]) -> list[list[int]]:
        return word[1:] + word[:1]

    def _sub_word(self, word: list[list[int]]) -> list[list[int]]:
        for row in range(WORD_SIZE):
            value = word[row][0] & 0xFF
            word[row][0] = AesTables.S_BOX[value >> 4][value & 0x0F]
        return word

    def key_schedule(self, key: int) -> None:
        """Expand a 128-bit key into eleven round keys."""
        if not isinstance(key, int) or not 0 <= key < (1 << 128):
            raise ValueError("key must be an unsigned 128-bit integer")

        self._set_key(key)
        for column in range(WORD_SIZE, WORD_SIZE * (TOTAL_ROUND + 1)):
            if column % WORD_SIZE == 0:
                previous_word = self._copy_word(column - 1)
                transformed_word = self._sub_word(self._rot_word(previous_word))
                round_index = column // WORD_SIZE - 1
                for row in range(WORD_SIZE):
                    self._words[row][column] = (
                        self._words[row][column - WORD_SIZE]
                        ^ transformed_word[row][0]
                        ^ AesTables.R_CON[row][round_index]
                    )
            else:
                for row in range(WORD_SIZE):
                    self._words[row][column] = (
                        self._words[row][column - WORD_SIZE]
                        ^ self._words[row][column - 1]
                    )

    def get_round_key(self, round_index: int) -> int:
        """Return a round key as a 128-bit integer."""
        if not 0 <= round_index <= TOTAL_ROUND:
            raise ValueError(f"round_index must be between 0 and {TOTAL_ROUND}")

        round_key = 0
        start_column = round_index * WORD_SIZE
        for column in range(start_column, start_column + WORD_SIZE):
            for row in range(WORD_SIZE):
                round_key = (round_key << 8) | (self._words[row][column] & 0xFF)
        return round_key
