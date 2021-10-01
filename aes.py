from utilities import aes_boxes
from functools import lru_cache


def block_val(index: int, data: list[int]) -> int:
    if len(data) <= index:
        return 16 - (len(data) % 16)
    return data[index]


def fill_block(block_index: int, data: list[int]) -> list[int]:
    return [block_val(block_index * 16 + index, data) for index in range(16)]


def populate_blocks(data: list[int]) -> list[list[int]]:
    block_count = int(len(data) / 16)
    block_count += 1
    blocks = []
    for block in range(block_count):
        blocks.append(fill_block(block, data))

    return blocks


def tc_helper(val: int) -> int:
    if val > 255:
        return (val ^ 0x1B) % 256
    return val


@lru_cache
def calculate_rc(round_num: int) -> int:
    if round_num == 1:
        return 1
    return tc_helper(2 * calculate_rc(round_num - 1))


def gen_round_constant() -> list[int]:
    for round_num in range(1, 11):
        yield [calculate_rc(round_num), 0, 0, 0]


def create_round_key(prev_round_key: list[int], round_constant: list[int]) -> list[int]:
    word = prev_round_key[13:] + [prev_round_key[12]]
    round_key = []

    for i in range(4):
        subbed_byte = aes_boxes.forwardsbox[word[i]]
        round_key.append(subbed_byte ^ round_constant[i] ^ prev_round_key[i])
    for i in range(12):
        round_key.append(prev_round_key[i + 4] ^ round_key[i])

    return round_key


def generate_round_keys(key_block: list[int]) -> list[int]:
    round_constants = gen_round_constant()
    last_round_key = key_block
    yield key_block
    for round_constant in range(1, 11):
        round_key = create_round_key(last_round_key, next(round_constants))
        last_round_key = round_key
        yield round_key


def sub_bytes(state: list[int]) -> list[int]:
    return [aes_boxes.forwardsbox[i] for i in state]


def inverse_sub_bytes(state: list[int]) -> list[int]:
    return [aes_boxes.backwardbox[i] for i in state]


def shift_rows(state: list[int]) -> list[int]:
    state = [state[i : i + 4] for i in range(0, 16, 4)]
    state = [i for j in zip(*state) for i in j]
    for row in range(4):
        state[row * 4 : (row + 1) * 4] = (
            state[row * 4 + row : (row + 1) * 4]
            + state[row * 4 : (row + 1) * 4 - (4 - row)]
        )
    state = [state[i : i + 4] for i in range(0, 16, 4)]
    state = [i for j in zip(*state) for i in j]
    return state


def inverse_shift_rows(state: list[int]) -> list[int]:
    state = [state[i : i + 4] for i in range(0, 16, 4)]
    state = [i for j in zip(*state) for i in j]
    for row in range(4):
        state[row * 4 : (row + 1) * 4] = (
            state[(row + 1) * 4 - row : (row + 1) * 4]
            + state[row * 4 : (row + 1) * 4 - row]
        )
    state = [state[i : i + 4] for i in range(0, 16, 4)]
    state = [i for j in zip(*state) for i in j]
    return state


def mix_columns_helper(index: int, val: int, i: int) -> int:
    special_vals = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]
    special_val = special_vals[index * 4 + i]

    if special_val == 1:
        return val
    elif special_val == 2:
        return tc_helper(val * 2)
    elif special_val == 3:
        return tc_helper(val * 2) ^ val


def mix_columns_tile(state: list[int], index: int) -> int:
    newval = 0
    for i in range(4):
        newval ^= mix_columns_helper(index % 4, state[int(index / 4) * 4 + i], i)
    return newval


def mix_columns(state: list[int]) -> list[int]:
    newstate = []
    for index in range(16):
        newstate.append(mix_columns_tile(state, index))
    return newstate


def inverse_mix_columns(state: list[int]) -> list[int]:
    for i in range(3):
        state = mix_columns(state)
    return state


def add_round_key(state: list[int], round_key: list[int]) -> list[int]:
    for index in range(16):
        state[index] = state[index] ^ round_key[index]
    return state


def encrypt_round(state: list[int], round_key: list[int], round_num: int) -> list[int]:
    state = sub_bytes(state)
    state = shift_rows(state)
    if round_num != 10:
        state = mix_columns(state)
    state = add_round_key(state, round_key)
    return state


def decrypt_round(state: list[int], round_key: list[int], round_num: int) -> list[int]:
    state = add_round_key(state, round_key)
    if round_num != 10:
        state = inverse_mix_columns(state)
    state = inverse_shift_rows(state)
    state = inverse_sub_bytes(state)
    return state


def finalise_decrypt(
    state: list[int],
    iv: list[int],
    key_block: list[int],
    inputs: list[list[int]],
    block_index: int,
    index: int,
) -> int:
    if block_index == 0:
        return state[index] ^ iv[index] ^ key_block[index]
    return state[index] ^ inputs[block_index - 1][index] ^ key_block[index]


def encrypt_block(
    state: list[int], key_block: list[int], input_block: list[int]
) -> list[int]:
    round_keys = generate_round_keys(key_block)
    next(round_keys)
    for index in range(16):
        state[index] ^= input_block[index] ^ key_block[index]

    for round_num in range(1, 11):
        state = encrypt_round(state, next(round_keys), round_num)

    return state


def decrypt_block(
    key_block: list[int],
    iv: list[int],
    inputs: list[list[int]],
    block_index: int,
) -> list[int]:
    round_keys = list(generate_round_keys(key_block))
    state = [
        i for i in inputs[block_index]
    ]  # This is necessary because of python's memory management
    for round_num in range(10, 0, -1):
        state = decrypt_round(state, round_keys[round_num], round_num)
    for index in range(16):
        state[index] = finalise_decrypt(
            state, iv, key_block, inputs, block_index, index
        )
    return state


def encrypt_blocks(
    inputs: list[list[int]], key_block: list[int], iv: list[int]
) -> list[int]:
    output = []
    state = iv
    for block_index in range(len(inputs)):
        state = encrypt_block(state, key_block, inputs[block_index])
        output.extend(state)
    return output


def decrypt_blocks(
    enc: list[list[int]], key_block: list[int], iv: list[int]
) -> list[int]:
    output = []
    for block_index in range(len(enc)):
        output.extend(decrypt_block(key_block, iv, enc, block_index))
    return output


def encrypt_bytes(plaintext: bytes, key: str, iv: list[int]) -> list[int]:
    blocks = populate_blocks(plaintext)
    key_block = populate_blocks(key.encode())[0]
    return encrypt_blocks(blocks, key_block, iv)


def decrypt_bytes(ciphertext: bytes, key: str, iv: list[int]) -> list[int]:
    blocks = populate_blocks(ciphertext)[:-1]
    key_block = populate_blocks(key.encode())[0]
    out = decrypt_blocks(blocks, key_block, iv)
    ### Process padding
    last_byte = out[-1]
    for i in range(2, last_byte):
        if out[-i] != last_byte:
            return out
    return out[:-last_byte]