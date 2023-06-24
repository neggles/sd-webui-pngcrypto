#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script to decrypt and extract the metadata from a file encrypted with the
sd-webui-pngcrypto extension, without having the webui installed.
"""
import argparse
import logging
from pathlib import Path
from typing import List

from PIL import Image

from scripts.crypto import MAX_LEN, CompType, PixelBitArray, PNGCryptor, StealthEnc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()  # root logger, standalone script

parser = argparse.ArgumentParser(description="Decrypt pngcrypto'd metadata")
parser.add_argument("password", type=str, help="The password used to encrypt the PNG file")
parser.add_argument("filename", type=Path, help="The encrypted PNG file to decrypt")


def read_stealth_pnginfo(image: Image.Image):
    mode = StealthEnc.RGBA if image.mode == "RGBA" else StealthEnc.RGB

    width, height = image.size
    pixels = image.load()

    buffer: List[int] = []
    for row in range(height):
        for col in range(width):
            index = row * width + col
            if mode == StealthEnc.RGB:
                index = index * 3

            if mode == StealthEnc.RGBA:
                buffer.append(pixels[col, row][3] & 1)
            else:
                buffer.append(pixels[col, row][0] & 1)
                buffer.append(pixels[col, row][1] & 1)
                buffer.append(pixels[col, row][2] & 1)

            if index >= MAX_LEN:
                break
        if index >= MAX_LEN:
            break
    return buffer


def extract_payload(image_path: Path, password: str) -> None:
    """Extract the payload from an encrypted PNG file."""
    if not image_path.exists():
        raise FileNotFoundError(f"File not found: {image_path}")

    image_obj = Image.open(image_path)
    _ = image_obj.load()

    # read stealth info from the image
    buffer = read_stealth_pnginfo(image_obj)
    # Create our magical bit array
    pixel_bits = PixelBitArray.from_int_array(buffer)

    # Ask it to unpack itself
    unpacked_sig, unpacked_ctxt = pixel_bits.unpack()
    # Split the signature into its parts
    magic, encoding, comp, enctype = unpacked_sig.decode("utf-8").split("_", 3)

    # brief sanity check
    if magic != "encrypted":
        raise ValueError(f"Invalid signature: {magic}")

    # tell user things are working
    logger.info(f"Found encrypted payload signature: {unpacked_sig}")

    # decode the enums
    comp = CompType(comp.decode("utf-8"))
    encoding = StealthEnc(encoding.decode("utf-8"))

    # split the enctype into its parts (kdf, cipher, bits, mode)
    kdf, cipher, bits, mode = enctype.decode("utf-8").split("-")

    # we only support one kdf because there's literally no point to more than one
    if kdf != "scrypt15":
        raise ValueError(f"Invalid KDF: {kdf}")

    # instantiate the decryptor
    decryptor = PNGCryptor(f"{cipher}-{bits}-{mode}", webui=False)
    # set the password, this triggers the hashing
    decryptor.password = password
    # do the actual decryption
    decrypted_text = decryptor.decrypt(unpacked_ctxt)
    # decompress the decrypted text
    geninfo = comp.decompress(decrypted_text).decode("utf-8")

    # print the metadata
    print(f"Successfully decrypted metadata: {geninfo}")
    meta_file = image_path.with_suffix(".txt")

    # save it next to the original file
    print(f"Saving to {meta_file}")
    meta_file.write_text(geninfo)

    print("Done!")
    exit(0)


if __name__ == "__main__":
    args = parser.parse_args()
    extract_payload(Path(args.filename), args.password)
