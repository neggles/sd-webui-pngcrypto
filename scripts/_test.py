import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd().joinpath("extensions", "sd-webui-pngcrypto", "scripts")))

from pngcrypto import CompType, PixelBitArray, PNGCryptor, StealthEnc  # noqa: E402

infotexts: str = "holy fucking bingle batman! what a savings!"
cryptor: PNGCryptor = PNGCryptor()
mode: StealthEnc = StealthEnc.RGBA
comp: CompType = CompType.GZIP

signature = f"encrypted_{mode.name}_{comp.name}_{cryptor.signature}__".encode("utf-8")

plaintext = comp.compress(infotexts.encode("utf-8"))  # compress is a no-op for info mode
ciphertext = cryptor.encrypt(plaintext)  # encrypt plaintext
ciphertext_len = f"{len(ciphertext) * 8:032b}".encode("utf-8")

pixel_bits = PixelBitArray(bytes(signature + ciphertext_len + ciphertext))
unpacked_sig, unpacked_ctxt = pixel_bits.unpack()

if unpacked_ctxt != ciphertext:
    raise ValueError("ciphertext and unpacked ciphertext no matchy")
if unpacked_sig != signature.decode().rstrip("__"):
    raise ValueError("signature and unpacked signature no matchy")


if False:
    # fmt: off
    int_array = [
    0, 1, 1, 0, 1, 0, 0, 0,
    0, 1, 1, 0, 1, 1, 1, 1,
    0, 1, 1, 0, 1, 1, 0, 0,
    0, 1, 1, 1, 1, 0, 0, 1,
    0, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 1, 1, 0,
    0, 1, 1, 1, 0, 1, 0, 1,
    0, 1, 1, 0, 0, 0, 1, 1,
    0, 1, 1, 0, 1, 0, 1, 1,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 1, 1, 0,
    0, 1, 1, 0, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 0, 0, 0, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 1, 1, 0,
    0, 1, 1, 0, 0, 1, 1, 1,
    0, 1, 1, 0, 1, 1, 0, 0,
    0, 1, 1, 0, 0, 1, 0, 1,
]
    # fmt: on

    # int_array = "".join([str(x) for x in int_array])

    bytearray(
        int("".join([str(x) for x in int_array[i : i + 8]]), 2) for i in range(0, len(int_array), 8)
    ).decode("utf-8", errors="ignore")
