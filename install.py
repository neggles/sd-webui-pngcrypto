import launch

if not launch.is_installed("pycryptodomex"):
    print("Installing pycryptodomex...")
    launch.run_pip("install pycryptodomex>=3.18.0", "requirements for pngcrypto")
