"""
PYNQ driver for the aes128_top IP
"""

from pynq import Overlay, MMIO, allocate
import time

# --- Register offsets, from xaes128_top_hw.h ---
REG_AP_CTRL    = 0x00   # bit0=ap_start, bit1=ap_done, bit2=ap_idle
REG_AP_RETURN  = 0x10   # always 0
REG_KEY_ADDR   = 0x18   # 64-bit pointer -> 2 words (low, high)
REG_INPUT_ADDR = 0x24   # 64-bit pointer -> 2 words (low, high)
REG_OUTPUT_ADDR = 0x30  # 64-bit pointer -> 2 words (low, high)
REG_MODE       = 0x3c   # 0 = encrypt, 1 = decrypt

AP_START = 1 << 0
AP_DONE  = 1 << 1
AP_IDLE  = 1 << 2

AES_KEY_SIZE = 16
AES_STATE_SIZE = 16


class AesAccel:
    def __init__(self, bitfile="aes_bd_wrapper.bit"):
        self.overlay = Overlay(bitfile)

        ip_info = self.overlay.ip_dict["aes128_top_0"]
        self.mmio = MMIO(ip_info["phys_addr"], ip_info["addr_range"])

        # Physical buffers shared with the IP
        self.key_buf = allocate(shape=(AES_KEY_SIZE,), dtype="u1")
        self.input_buf = allocate(shape=(AES_STATE_SIZE,), dtype="u1")
        self.output_buf = allocate(shape=(AES_STATE_SIZE,), dtype="u1")

    def _write_ptr(self, offset, physical_address):
        # 64-bit pointer split across two 32-bit registers
        self.mmio.write(offset, physical_address & 0xFFFFFFFF)
        self.mmio.write(offset + 4, (physical_address >> 32) & 0xFFFFFFFF)

    def _run(self, key: bytes, data: bytes, mode: int) -> bytes:
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"key must be {AES_KEY_SIZE} bytes")
        if len(data) != AES_STATE_SIZE:
            raise ValueError(f"block must be {AES_STATE_SIZE} bytes")

        self.key_buf[:] = list(key)
        self.input_buf[:] = list(data)

        self._write_ptr(REG_KEY_ADDR, self.key_buf.physical_address)
        self._write_ptr(REG_INPUT_ADDR, self.input_buf.physical_address)
        self._write_ptr(REG_OUTPUT_ADDR, self.output_buf.physical_address)
        self.mmio.write(REG_MODE, mode)

        self.mmio.write(REG_AP_CTRL, AP_START)
        while not (self.mmio.read(REG_AP_CTRL) & AP_DONE):
            time.sleep(0.0001)

        return bytes(self.output_buf.tobytes())

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        return self._run(key, plaintext, mode=0)

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        return self._run(key, ciphertext, mode=1)

    def close(self):
        self.key_buf.close()
        self.input_buf.close()
        self.output_buf.close()


if __name__ == "__main__":
    accel = AesAccel("aes_bd_wrapper.bit")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    ciphertext = accel.encrypt(key, plaintext)
    print("cipher:", ciphertext.hex())
    # Expected: 69c4e0d86a7b0430d8cdb78070b4c55a

    recovered = accel.decrypt(key, ciphertext)
    print("plain: ", recovered.hex())
    # Expected: 00112233445566778899aabbccddeeff

    accel.close()