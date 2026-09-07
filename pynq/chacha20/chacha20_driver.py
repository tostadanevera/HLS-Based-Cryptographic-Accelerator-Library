"""
PYNQ driver for the chacha20_top IP
"""

from pynq import Overlay, MMIO, allocate
import numpy as np
import time

# --- Register offsets, from xchacha20_top_hw.h ---
REG_AP_CTRL      = 0x00   # bit0=ap_start, bit1=ap_done, bit2=ap_idle
REG_AP_RETURN    = 0x10   # always 0
REG_KEY_ADDR     = 0x18   # 64-bit pointer -> 2 words (low, high)
REG_COUNTER      = 0x24
REG_NONCE_ADDR   = 0x2c   # 64-bit pointer -> 2 words (low, high)
REG_PLAIN_ADDR   = 0x38   # 64-bit pointer -> 2 words (low, high)
REG_CIPHER_ADDR  = 0x44   # 64-bit pointer -> 2 words (low, high)
REG_LENGTH       = 0x50

AP_START = 1 << 0
AP_DONE  = 1 << 1
AP_IDLE  = 1 << 2

CHACHA_KEY_BYTES     = 32
CHACHA_NONCE_BYTES   = 12
CHACHA_MAX_MESSAGE_BYTES = 1024


class ChaCha20Accel:
    def __init__(self, bitfile="chacha20_bd_wrapper.bit"):
        self.overlay = Overlay(bitfile)

        ip_info = self.overlay.ip_dict["chacha20_top_0"]
        self.mmio = MMIO(ip_info["phys_addr"], ip_info["addr_range"])

        # Physical buffers shared with the IP
        self.key_buf = allocate(shape=(CHACHA_KEY_BYTES // 4,), dtype="u4")
        self.nonce_buf = allocate(shape=(CHACHA_NONCE_BYTES // 4,), dtype="u4")
        self.plaintext_buf = allocate(shape=(CHACHA_MAX_MESSAGE_BYTES,), dtype="u1")
        self.ciphertext_buf = allocate(shape=(CHACHA_MAX_MESSAGE_BYTES,), dtype="u1")

    def _write_ptr(self, offset, physical_address):
        # 64-bit pointer split across two 32-bit registers
        self.mmio.write(offset, physical_address & 0xFFFFFFFF)
        self.mmio.write(offset + 4, (physical_address >> 32) & 0xFFFFFFFF)

    def encrypt(self, key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
        if len(key) != CHACHA_KEY_BYTES:
            raise ValueError(f"key must be {CHACHA_KEY_BYTES} bytes")
        if len(nonce) != CHACHA_NONCE_BYTES:
            raise ValueError(f"nonce must be {CHACHA_NONCE_BYTES} bytes")
        if len(plaintext) > CHACHA_MAX_MESSAGE_BYTES:
            raise ValueError(
                f"message of {len(plaintext)} bytes exceeds the max "
                f"{CHACHA_MAX_MESSAGE_BYTES} supported by the core"
            )

        # key/nonce are packed little-endian into 32-bit words, same as
        # bytes_to_words_le() in the C++ testbenches
        self.key_buf[:] = np.frombuffer(key, dtype="<u4")
        self.nonce_buf[:] = np.frombuffer(nonce, dtype="<u4")
        self.plaintext_buf[: len(plaintext)] = list(plaintext)

        self._write_ptr(REG_KEY_ADDR, self.key_buf.physical_address)
        self._write_ptr(REG_NONCE_ADDR, self.nonce_buf.physical_address)
        self._write_ptr(REG_PLAIN_ADDR, self.plaintext_buf.physical_address)
        self._write_ptr(REG_CIPHER_ADDR, self.ciphertext_buf.physical_address)
        self.mmio.write(REG_COUNTER, counter)
        self.mmio.write(REG_LENGTH, len(plaintext))

        self.mmio.write(REG_AP_CTRL, AP_START)
        while not (self.mmio.read(REG_AP_CTRL) & AP_DONE):
            time.sleep(0.0001)

        return bytes(self.ciphertext_buf[: len(plaintext)].tobytes())

    def decrypt(self, key: bytes, counter: int, nonce: bytes, ciphertext: bytes) -> bytes:
        # ChaCha20 is symmetric: decryption is the same keystream XOR
        return self.encrypt(key, counter, nonce, ciphertext)

    def close(self):
        self.key_buf.close()
        self.nonce_buf.close()
        self.plaintext_buf.close()
        self.ciphertext_buf.close()


if __name__ == "__main__":
    accel = ChaCha20Accel("chacha20_bd_wrapper.bit")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"[:64])
    nonce = bytes.fromhex("000000000000004a00000000"[:24])
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373"
        "206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c"
        "79206f6e652074697020666f7220746865206675747572652c2073756e73637265"
        "656e20776f756c642062652069742e"
    )

    ciphertext = accel.encrypt(key, 1, nonce, plaintext)
    print("cipher:", ciphertext.hex())
    # Expected (RFC 8439): 6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0...

    accel.close()