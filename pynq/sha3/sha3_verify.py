import time
from sha3_driver import Sha3Accel

# Same vectors as test_sha3_top.cpp (NIST CAVS "SHA3-256 ShortMsg")
TEST_VECTORS = [
    ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ("e9", "f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6"),
    ("d477", "94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7"),
    ("e7372105", "3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae"),
    ("8bca931c8a132d2f", "dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e"),
    ("d83c721ee51b060c5a41438a8221e040", "b87d9e4722edd3918729ded9a6d03af8256998ee088a1ae662ef4bcaff142a96"),
    ("c178ce0f720a6d73c6cf1caa905ee724d5ba941c2e2628136e3aad7d853733ba", "64537b87892835ff0963ef9ad5145ab4cfce5d303a0cb0415b3b03f9d16e7d6b"),
    ("67e384d209f1bc449fa67da6ce5fbbe84f4610129f2f0b40f7c0caea7ed5cb69be22ffb7541b2077ec1045356d9db4ee7141f7d3f84d324a5d00b33689f0cb78", "9c9160268608ef09fe0bd3927d3dffa0c73499c528943e837be467b50e5c1f1e"),
    ("84b60cb3720bf29748483cf7abd0d1f1d9380459dfa968460c86e5d1a54f0b19dac6a78bf9509460e29dd466bb8bdf04e5483b782eb74d6448166f897add43d295e946942ad9a814fab95b4aaede6ae4c8108c8edaeff971f58f7cf96566c9dc9b6812586b70d5bc78e2f829ec8e179a6cd81d224b161175fd3a33aacfb1483f", "8814630a39dcb99792cc4e08cae5dd078973d15cd19f17bacf04deda9e62c45f"),
]


def main():
    accel = Sha3Accel("sha3_bd_wrapper.bit")

    total = 0
    passed = 0
    durations = []

    for message_hex, expected_hex in TEST_VECTORS:
        total += 1
        msg_bytes = bytes.fromhex(message_hex)

        start = time.perf_counter()
        try:
            result = accel.compute(msg_bytes)
            elapsed = time.perf_counter() - start
            durations.append(elapsed)

            got_hex = result.hex()
            ok = (got_hex == expected_hex)
        except RuntimeError as e:
            elapsed = time.perf_counter() - start
            durations.append(elapsed)
            got_hex = str(e)
            ok = False

        label = f"len={len(msg_bytes)}B"
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {label}  hash={got_hex}")
        if not ok:
            print(f"       expected: {expected_hex}")

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

    if durations:
        stats("compute", durations)


if __name__ == "__main__":
    main()