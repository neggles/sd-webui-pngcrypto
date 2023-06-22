from argparse import ArgumentParser


def preload(parser: ArgumentParser):
    parser.add_argument(
        "--pngcrypto-secret",
        type=str,
        help="Password to use for PNGCrypto encryption (defaults to last saved password or a 16-character random string)",
        default=None,
    )
