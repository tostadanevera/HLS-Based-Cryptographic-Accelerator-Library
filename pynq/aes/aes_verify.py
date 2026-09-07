import time
from aes_driver import AesAccel

# Same vectors as test_aes.cpp
TEST_VECTORS = [
    ("00000000000000000000000000000000", "f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e"),
    ("00000000000000000000000000000000", "9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589"),
    ("00000000000000000000000000000000", "96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597"),
    ("00000000000000000000000000000000", "6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209"),
    ("00000000000000000000000000000000", "cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce"),
    ("10a58869d74be5a374cf867cfb473859", "00000000000000000000000000000000", "6d251e6944b051e04eaa6fb4dbf78465"),
    ("caea65cdbb75e9169ecd22ebe6e54675", "00000000000000000000000000000000", "6e29201190152df4ee058139def610bb"),
    ("a2e2fa9baf7d20822ca9f0542f764a41", "00000000000000000000000000000000", "c3b44b95d9d2f25670eee9a0de099fa3"),
    ("b6364ac4e1de1e285eaf144a2415f7a0", "00000000000000000000000000000000", "5d9b05578fc944b3cf1ccf0e746cd581"),
    ("64cf9c7abc50b888af65f49d521944b2", "00000000000000000000000000000000", "f7efc89d5dba578104016ce5ad659c05"),
    ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
    ("2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
    ("2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
    ("2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
    ("00000000000000000000000000000000", "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e"),
    ("ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff", "bcbf217cb280cf30b2517052193ab979"),
    ("00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "7aca0fd9bcd6ec7c9f97466616e6a282"),
    ("000102030405060708090a0b0c0d0e0f", "ffffffffffffffffffffffffffffffff", "3c441f32ce07822364d7a2990e50bb13"),
]


def main():
    accel = AesAccel("aes_bd_wrapper.bit")

    total = 0
    passed = 0
    enc_durations = []
    dec_durations = []

    for key_hex, plain_hex, cipher_hex in TEST_VECTORS:
        total += 1
        key = bytes.fromhex(key_hex[:32])
        plain = bytes.fromhex(plain_hex[:32])
        expected_cipher = bytes.fromhex(cipher_hex[:32])

        start = time.perf_counter()
        got_cipher = accel.encrypt(key, plain)
        enc_durations.append(time.perf_counter() - start)
        enc_ok = (got_cipher == expected_cipher)

        start = time.perf_counter()
        got_plain = accel.decrypt(key, expected_cipher)
        dec_durations.append(time.perf_counter() - start)
        dec_ok = (got_plain == plain)

        ok = enc_ok and dec_ok
        status = "OK" if ok else "FAIL"
        print(f"[{status}] key={key_hex[:32]}")
        if not enc_ok:
            print(f"       encrypt got:      {got_cipher.hex()}")
            print(f"       encrypt expected: {expected_cipher.hex()}")
        if not dec_ok:
            print(f"       decrypt got:      {got_plain.hex()}")
            print(f"       decrypt expected: {plain.hex()}")

        if ok:
            passed += 1

    accel.close()

    print()
    print(f"{passed}/{total} passed")

    def stats(label, durations):
        avg_ms = sum(durations) / len(durations) * 1e3
        min_ms = min(durations) * 1e3
        max_ms = max(durations) * 1e3
        print(f"{label} latency: avg={avg_ms:.3f} ms  min={min_ms:.3f} ms  max={max_ms:.3f} ms")

    if enc_durations:
        stats("encrypt", enc_durations)
    if dec_durations:
        stats("decrypt", dec_durations)


if __name__ == "__main__":
    main()