import logging
import warnings
from dataclasses import InitVar, dataclass
from enum import Enum
from gzip import compress, decompress
from typing import TYPE_CHECKING, List, SupportsIndex, Tuple

import gradio as gr
from gradio import processing_utils
from modules import generation_parameters_copypaste, images, script_callbacks, shared
from PIL import Image, ImageOps

if TYPE_CHECKING:
    from modules.script_callbacks import ImageSaveParams

from crypto import PNGCryptor

# create logger
logger = logging.getLogger(__name__)
# create cryptor object
cryptor = PNGCryptor("AES-256-EAX")


class StealthEnc(str, Enum):
    png = "Alpha channel"
    rgb = "RGB channels"
    # Recklessly abusing that the first defined name of a value is what .name always returns
    RGBA = "Alpha channel"
    RGB = "RGB channels"


class CompType(str, Enum):
    info = "No compression"
    comp = "Gzip (default)"
    zstd = "Zstandard (experimental)"
    # further enum abuse!
    GZIP = "Gzip (default)"
    ZSTD = "Zstandard (experimental)"

    # a method? on MYYYY enum? it's more likely than you think!
    def compress(self, data: bytes) -> bytes:
        if self == CompType.info:
            return data
        elif self == CompType.GZIP:
            return compress(data)
        elif self == CompType.zstd:
            raise NotImplementedError("ZSTD compression is not implemented yet")
        # should never happen
        raise ValueError(f"Unknown compression type {self.value}")

    def decompress(self, data: bytes) -> bytes:
        if self == CompType.info:
            return data
        elif self == CompType.GZIP:
            return decompress(data)
        elif self == CompType.zstd:
            raise NotImplementedError("ZSTD compression is not implemented yet")
        # should never happen
        raise ValueError(f"Unknown compression type {self.value}")


@dataclass
class PixelBitArray:
    """This is cursed.
    It's a bytearray that you can index into the individual bits of like they were a list,
    and its init method takes a bytes object.
    Also there's a from_int_array class method that takes a list of ints/bools.
    Makes for easier conversion between "list of ints" and "array of bytes" and vice versa.
    """

    data: InitVar[bytes] = b""

    def __post_init__(self, data: bytes):
        self._data = bytearray(data)

    def __getitem__(self, __key: SupportsIndex) -> int:
        return (self._data[__key // 8] >> (7 - __key % 8)) & 1

    def __setitem__(self, __key: SupportsIndex, __value: SupportsIndex):
        self._data[__key // 8] |= (__value & 1) << (7 - __key % 8)
        pass

    def __len__(self) -> int:
        return len(self._data) * 8

    def __repr__(self) -> str:
        return f"PixelBitArray({self._data})"

    def __str__(self) -> str:
        return self._data.decode(encoding="utf-8")

    def rgba(self, pixel: Tuple[int, int, int, int], index: int) -> Tuple[int, int, int]:
        # XOR the alpha channel's LSB with the bit at idx and return the pixel
        return tuple(pixel[0], pixel[1], pixel[2], pixel[3] ^ self[index])

    def rgb(self, pixel: Tuple[int, int, int], index: int) -> Tuple[int, int, int]:
        # XOR the R, G and B channels' LSBs with the bits at idx:idx+2 and return the pixel
        return tuple(pixel[i] ^ self[index + i] for i in range(3))

    def decode(self, errors="ignore") -> str:
        return self._data.decode(encoding="utf-8", errors=errors)

    def get_meta(self) -> Tuple[str, int, int]:
        sig, trailer = self.decode().split("__", 1)
        offset = len(sig) + 2 + 32  # 2 for the __, 32 for the length
        payload_bytes = int(trailer[:32], 2) // 8
        return sig, offset, payload_bytes

    def unpack(self) -> Tuple[str, bytes]:
        sig, offset, payload_bytes = self.get_meta()
        payload = self._data[offset : offset + payload_bytes]
        return sig, bytes(payload)

    @classmethod
    def from_int_array(cls, data: list[int]) -> "PixelBitArray":
        return cls(bytes(int("".join([str(x) for x in data[i : i + 8]]), 2) for i in range(0, len(data), 8)))


def prepare_data(
    infotexts: str,
    cryptor: PNGCryptor,
    mode: StealthEnc = StealthEnc.RGBA,
    comp: CompType = CompType.GZIP,
) -> PixelBitArray:
    # e.g. "encrypted_pngcomp_scrypt15-aes-256-eax__"
    signature = f"encrypted_{mode.name}_{comp.name}_{cryptor.signature}__".encode("utf-8")
    plaintext = comp.compress(infotexts.encode("utf-8"))  # compress is a no-op for info mode
    ciphertext = cryptor.encrypt(plaintext)  # encrypt plaintext
    ciphertext_len = f"{len(ciphertext) * 8:032b}".encode("utf-8")
    return PixelBitArray(signature + ciphertext_len + ciphertext)


def add_data(
    params: "ImageSaveParams",
    cryptor: PNGCryptor,
    mode: StealthEnc = StealthEnc.RGBA,
    comp: CompType = CompType.GZIP,
):
    binary_data: PixelBitArray = prepare_data(
        infotexts=params.pnginfo["parameters"],
        cryptor=cryptor,
        mode=mode,
        comp=comp,
    )
    if mode == StealthEnc.RGBA:
        params.image.putalpha(255)

    width, height = params.image.size
    pixels = params.image.load()
    for ypos in range(height):
        for xpos in range(width):
            index = ypos * width + xpos  # get current pixel number
            if mode == StealthEnc.RGB:
                index = index * 3  # RGB mode is 3bpp so multiply index pos
            if index >= len(binary_data):
                break  # break if we've reached the end of the data
            if mode == StealthEnc.RGB:
                pixels[xpos, ypos] = binary_data.rgb(pixels[xpos, ypos], index)
            else:
                pixels[xpos, ypos] = binary_data.rgba(pixels[xpos, ypos], index)
        if index >= len(binary_data):
            break  # break if we've reached the end of the data


def add_pngcrypto(params: "ImageSaveParams"):
    global cryptor
    pngcrypto_enabled = shared.opts.data.get("pngcrypto", True)
    pngcrypto_cipher = shared.opts.data.get("pngcrypto_cipher", PNGCryptor.DEFAULT_MODE)
    pngcrypto_comp = CompType(shared.opts.data.get("pngcrypto_comp", CompType.GZIP.value))
    pngcrypto_mode = StealthEnc(shared.opts.data.get("pngcrypto_mode", StealthEnc.RGBA.value))

    if pngcrypto_enabled is False or params.pnginfo is None:
        return  # do nothing if pngcrypto is disabled or no pnginfo is present

    if cryptor.name != pngcrypto_cipher:
        cryptor = PNGCryptor(pngcrypto_cipher)  # update cryptor if mode has changed

    if params.filename.lower().endswith(".png") and "parameters" in params.pnginfo:
        add_data(params, cryptor, pngcrypto_mode, pngcrypto_comp)


def read_info_from_image_encrypted(image: Image.Image):
    geninfo, items = original_read_info_from_image(image)

    # respecting original pnginfo
    if geninfo is not None:
        return geninfo, items

    MAX_LEN = 16384 * 8  # 16k chars is *plenty* so we'll cap it there
    mode = StealthEnc.RGBA if image.mode == "RGBA" else StealthEnc.RGB

    # trying to read encrypted pnginfo
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

    try:
        # Create our magical bit array
        pixel_bits = PixelBitArray.from_int_array(buffer)
        # Ask it to unpack itself
        unpacked_sig, unpacked_ctxt = pixel_bits.unpack()
        # Split the signature into its parts
        magic, encoding, comp, encryption = unpacked_sig.decode("utf-8").split("_", 3)

        if magic != "encrypted":
            raise ValueError(f"Invalid signature: {magic}")
        if encoding != mode.name:
            warnings.warn(f"Invalid encoding: {encoding}. Expected {mode.name}, will try anyway...")

        comp = CompType(comp.decode("utf-8"))
        kdf, cipher, bits, mode = encryption.decode("utf-8").split("-")
        if kdf != "scrypt15":
            raise ValueError(f"Unsupported KDF: {kdf}")

        decryptor = PNGCryptor(f"{cipher}-{bits}-{mode}")
        decrypted_text = decryptor.decrypt(unpacked_ctxt)
        geninfo = comp.decompress(decrypted_text)
    except Exception:
        logging.exception("Failed to read encrypted pnginfo")
    finally:
        return geninfo, items


def send_rgb_image_and_dimension(x):
    if isinstance(x, Image.Image):
        img = x
        if img.mode == "RGBA":
            img = img.convert("RGB")
    else:
        img = generation_parameters_copypaste.image_from_url_text(x)
        if img.mode == "RGBA":
            img = img.convert("RGB")

    if shared.opts.send_size and isinstance(img, Image.Image):
        w = img.width
        h = img.height
    else:
        w = gr.update()
        h = gr.update()

    return img, w, h


def custom_image_preprocess(self: gr.Image, x):
    if x is None:
        return x

    mask = ""
    if self.tool == "sketch" and self.source in ["upload", "webcam"]:
        assert isinstance(x, dict)
        x, mask = x["image"], x["mask"]

    assert isinstance(x, str)
    im = processing_utils.decode_base64_to_image(x)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        im = im.convert(self.image_mode)
    if self.shape is not None:
        im = processing_utils.resize_and_crop(im, self.shape)
    if self.invert_colors:
        im = ImageOps.invert(im)
    if self.source == "webcam" and self.mirror_webcam is True and self.tool != "color-sketch":
        im = ImageOps.mirror(im)

    if self.tool == "sketch" and self.source in ["upload", "webcam"]:
        mask_im = None
        if mask is not None:
            mask_im = processing_utils.decode_base64_to_image(mask)

        return {
            "image": self._format_image(im),
            "mask": self._format_image(mask_im),
        }

    return self._format_image(im)


def on_after_component_change_pnginfo_image_mode(component, **_kwargs):
    if type(component) is gr.State:
        return
    if type(component) is gr.Image and component.elem_id == "pnginfo_image":
        component.image_mode = "RGBA"

    def clear_alpha(param):
        print("clear_alpha called")
        output_image = param["image"].convert("RGB")
        return output_image

    if type(component) is gr.Image and component.elem_id == "img2maskimg":
        component.upload(clear_alpha, component, component)
        component.preprocess = custom_image_preprocess.__get__(component, gr.Image)


def encrypted_resize_image(resize_mode, im, width, height, upscaler_name=None):
    """
    Resizes an image with the specified resize_mode, width, and height.

    Args:
        resize_mode: The mode to use when resizing the image.
            0: Resize the image to the specified width and height.
            1: Resize the image to fill the specified width and height, maintaining the aspect ratio, and then center the image within the dimensions, cropping the excess.
            2: Resize the image to fit within the specified width and height, maintaining the aspect ratio, and then center the image within the dimensions, filling empty with data from image.
        im: The image to resize.
        width: The width to resize the image to.
        height: The height to resize the image to.
        upscaler_name: The name of the upscaler to use. If not provided, defaults to opts.upscaler_for_img2img.
    """
    # convert to RGB
    if im.mode == "RGBA":
        im = im.convert("RGB")

    return original_resize_image(resize_mode, im, width, height, upscaler_name)


def on_ui_settings():
    section = ("pngcrypto", "PNGcrypto")
    shared.opts.add_option(
        "pngcrypto",
        shared.OptionInfo(
            True,
            "PNGcrypto enable",
            gr.Checkbox,
            {"interactive": True},
            section=section,
        ),
    )
    shared.opts.add_option(
        "pngcrypto_cipher",
        shared.OptionInfo(
            PNGCryptor.DEFAULT_MODE,
            "PNGcrypto encryption",
            gr.Dropdown,
            {"choices": PNGCryptor.AVAIL_MODES, "interactive": True},
            section=section,
        ),
    )
    shared.opts.add_option(
        "pngcrypto_comp",
        shared.OptionInfo(
            CompType.GZIP.value,
            "PNGcrypto compression",
            gr.Dropdown,
            {"choices": list(set(x.value for x in CompType)), "interactive": True},
            section=section,
        ),
    )
    shared.opts.add_option(
        "pngcrypto_mode",
        shared.OptionInfo(
            StealthEnc.RGBA.value,
            "PNGcrypto encoding",
            gr.Dropdown,
            {"choices": list(set(x.value for x in StealthEnc)), "interactive": True},
            section=section,
        ),
    )


# Override read_info_from_image to read the encrypted pnginfo, encrypted or otherwise
original_read_info_from_image = images.read_info_from_image
images.read_info_from_image = read_info_from_image_encrypted

# Override send_image_and_dimensions to send let us embed encrypted encrypted pnginfo
generation_parameters_copypaste.send_image_and_dimensions = send_rgb_image_and_dimension

# Override resize_image to maintain pixel-embedded pnginfo
original_resize_image = images.resize_image
images.resize_image = encrypted_resize_image

# add callbacks
script_callbacks.on_ui_settings(on_ui_settings)
script_callbacks.on_before_image_saved(add_pngcrypto)
script_callbacks.on_after_component(on_after_component_change_pnginfo_image_mode)
