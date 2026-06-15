"""AES-128 block cipher with ECB/CBC helpers."""

from __future__ import annotations

from .utils import pkcs7_pad, pkcs7_unpad, split_blocks, xor_bytes

BLOCK_SIZE = 16
NB = 4
NK = 4
NR = 10

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
INV_S_BOX = [0] * 256
for i, value in enumerate(S_BOX):
    INV_S_BOX[value] = i
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def _bytes_to_state(block: bytes) -> list[list[int]]:
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[row][col] for col in range(4) for row in range(4))


def _add_round_key(state: list[list[int]], words: list[list[int]], round_index: int) -> None:
    for col in range(4):
        word = words[round_index * 4 + col]
        for row in range(4):
            state[row][col] ^= word[row]


def _sub_bytes(state: list[list[int]], inverse: bool = False) -> None:
    box = INV_S_BOX if inverse else S_BOX
    for row in range(4):
        for col in range(4):
            state[row][col] = box[state[row][col]]


def _shift_rows(state: list[list[int]], inverse: bool = False) -> None:
    for row in range(1, 4):
        amount = -row if inverse else row
        state[row] = state[row][amount:] + state[row][:amount]


def _mix_columns(state: list[list[int]], inverse: bool = False) -> None:
    matrix = (14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14) if inverse else (
        2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2
    )
    for col in range(4):
        a = [state[row][col] for row in range(4)]
        for row in range(4):
            state[row][col] = (
                _gmul(matrix[row * 4], a[0])
                ^ _gmul(matrix[row * 4 + 1], a[1])
                ^ _gmul(matrix[row * 4 + 2], a[2])
                ^ _gmul(matrix[row * 4 + 3], a[3])
            )


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _sub_word(word: list[int]) -> list[int]:
    return [S_BOX[b] for b in word]


def _key_expansion(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES implementation supports 128-bit keys")
    words = [list(key[i : i + 4]) for i in range(0, len(key), 4)]
    for i in range(NK, NB * (NR + 1)):
        temp = words[i - 1].copy()
        if i % NK == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // NK]
        words.append([words[i - NK][j] ^ temp[j] for j in range(4)])
    return words


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")
    words = _key_expansion(key)
    state = _bytes_to_state(block)
    _add_round_key(state, words, 0)
    for round_index in range(1, NR):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, words, round_index)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, words, NR)
    return _state_to_bytes(state)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")
    words = _key_expansion(key)
    state = _bytes_to_state(block)
    _add_round_key(state, words, NR)
    for round_index in range(NR - 1, 0, -1):
        _shift_rows(state, inverse=True)
        _sub_bytes(state, inverse=True)
        _add_round_key(state, words, round_index)
        _mix_columns(state, inverse=True)
    _shift_rows(state, inverse=True)
    _sub_bytes(state, inverse=True)
    _add_round_key(state, words, 0)
    return _state_to_bytes(state)


def encrypt(data: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    mode = mode.upper()
    padded = pkcs7_pad(data, BLOCK_SIZE)
    if mode == "ECB":
        return b"".join(encrypt_block(block, key) for block in split_blocks(padded, BLOCK_SIZE))
    if mode != "CBC":
        raise ValueError("AES mode must be ECB or CBC")
    if iv is None:
        iv = bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("AES-CBC IV must be 16 bytes")
    out = []
    prev = iv
    for block in split_blocks(padded, BLOCK_SIZE):
        enc = encrypt_block(xor_bytes(block, prev), key)
        out.append(enc)
        prev = enc
    return b"".join(out)


def decrypt(data: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    mode = mode.upper()
    if mode == "ECB":
        plain = b"".join(decrypt_block(block, key) for block in split_blocks(data, BLOCK_SIZE))
        return pkcs7_unpad(plain, BLOCK_SIZE)
    if mode != "CBC":
        raise ValueError("AES mode must be ECB or CBC")
    if iv is None:
        iv = bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("AES-CBC IV must be 16 bytes")
    out = []
    prev = iv
    for block in split_blocks(data, BLOCK_SIZE):
        dec = xor_bytes(decrypt_block(block, key), prev)
        out.append(dec)
        prev = block
    return pkcs7_unpad(b"".join(out), BLOCK_SIZE)
