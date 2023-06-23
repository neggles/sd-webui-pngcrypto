import logging
import warnings
from base64 import b64encode
from dataclasses import dataclass, field
from os import urandom as random_bytes
from pathlib import Path
from typing import ClassVar, List, Optional, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_eax import EaxMode
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import scrypt
from modules import shared
from rsa import decrypt

SCRYPT_N = 15  # 32MB memory usage, about 75ms on a Platinum 8260 which is fine for this purpose

# we only store the base64 encoded sha256 hash in here
PASSWD_FILE = Path(__file__).parent.joinpath(".pngcrypto")
BACKUP_FILE = PASSWD_FILE.with_name(f"{PASSWD_FILE.name}.old")

logger = logging.getLogger(__name__)


def backup_passwd(crypto: "PNGCryptor"):
    # check if the hash changed, if so, warn the user
    if PASSWD_FILE.exists():
        existing_hash = PASSWD_FILE.read_text(encoding="utf-8").strip()
        if existing_hash != crypto.passhash:
            if BACKUP_FILE.exists():
                raise RuntimeError(
                    "pngcrypto: ERROR: password hash has changed but backup already exists, will not overwrite!"
                    + " Please delete the backup file manually if you don't need it anymore."
                )
            else:
                warnings.warn(
                    f"pngcrypto: WARNING: password hash changed from {existing_hash} to {crypto.passhash}!"
                    + "\nBacking up old hash to .pngcrypto.old, please delete it if you don't need it anymore."
                )
                PASSWD_FILE.rename(BACKUP_FILE)
                PASSWD_FILE.write_text(crypto.passhash, encoding="utf-8")
    else:
        # write the hash to disk
        logger.info("pngcrypto: writing password hash to disk")
        PASSWD_FILE.write_text(crypto.passhash, encoding="utf-8")


@dataclass
class PNGCryptor:
    """PNGCryptor is a dataclass that holds the mode of operation for PNGCrypto."""

    name: str = field(default="AES-256-EAX")
    kdf: str = field(init=False)
    bits: int = field(init=False)
    mode: int = field(init=False)
    passhash: str = field(init=False, repr=False)

    AVAIL_MODES: ClassVar[List[str]] = ["AES-128-EAX", "AES-256-EAX"]
    DEFAULT_MODE: ClassVar[str] = "AES-256-EAX"

    def __post_init__(self):
        """Create a new PNGCryptor object."""
        # make sure the name is uppercase
        self.name = self.name.upper()
        # split the name into cipher, bits, mode
        cipher, bits, mode = self.name.split("-")

        # check cipher
        if cipher != "AES":  # only allow AES because small block
            raise ValueError(f"Invalid cipher: {cipher} (must be AES)")
        # check key length
        self.bits = int(bits)
        if self.bits % 128:  # only allow 128/256 bit keys (192 is poorly supported and slow)
            raise ValueError(f"Invalid key size: {bits} (must be 128 or 256)")
        # check mode
        if mode not in ("EAX"):  # in this house we use authenticated encryption!
            raise ValueError(f"Invalid mode: {mode} (must be EAX)")
        else:
            self.mode = AES.MODE_EAX

        # KDF info string
        self.kdf = f"scrypt{SCRYPT_N}"

        # see if we got a password at the command line
        crypto_pass: Optional[str] = (
            shared.cmd_opts.pngcrypto_pass if hasattr(shared.cmd_opts, "pngcrypto_pass") else None
        )
        if crypto_pass is None:
            # no password, check if we have a hash stored
            if PASSWD_FILE.exists():
                self.passhash = PASSWD_FILE.read_text(encoding="utf-8").strip()
            else:
                # no hash, no commandline pass, generate a random password
                crypto_pass = random_bytes(8).hex()
                print(f"pngcrypto: generated random password: {crypto_pass}")
                self.password = crypto_pass
        else:
            # got a password at the command line, use it
            self.password = crypto_pass

    @property
    def signature(self) -> str:
        return f"{self.kdf}-{self.name}".lower()

    @property
    def password(self) -> None:
        """Password is not stored in plaintext, can only be set, not read."""
        raise AttributeError("Password is not stored in plaintext!")

    @password.setter
    def password(self, value: str) -> None:
        """Store SHA256 hash of password for later scrypting."""
        self.passhash = b64encode(SHA256.new(value.encode("utf-8")).digest()).decode("utf-8")
        backup_passwd(self)

    @password.deleter
    def password(self) -> None:
        self.passhash = None

    def _salt(self) -> bytes:
        """Get random salt for scrypt."""
        return random_bytes(32)

    def get_key_nonce(self, salt: bytes) -> Tuple[bytes, bytes]:
        if len(salt) != 32:
            raise ValueError("Salt must be 32 bytes long!")
        key, nonce = scrypt(
            self.passhash, salt=salt, key_len=self.bits // 128, N=2**SCRYPT_N, r=8, p=1, num_keys=2
        )
        return key, nonce

    def encrypt(self, data: bytes) -> bytes | Tuple[bytes, bytes, bytes]:
        """Encrypt data using the selected mode."""
        salt = self._salt()
        key, nonce = self.get_key_nonce(salt)
        cipher: EaxMode = AES.new(key=key, mode=self.mode, nonce=nonce, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return self.merge_salt_tag(salt, tag, ciphertext)

    def merge_salt_tag(self, salt: bytes, tag: bytes, data: bytes) -> bytes:
        return bytes(salt + tag + data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the selected mode."""
        salt, tag, ciphertext = self.split_salt_tag(data)
        key, nonce = self.get_key_nonce(salt)
        cipher: EaxMode = AES.new(key=key, mode=self.mode, nonce=nonce, mac_len=16)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def split_salt_tag(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """Split the salt and tag from the ciphertext."""
        return data[:32], data[32:48], data[48:]
