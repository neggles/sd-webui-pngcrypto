import launch

if not launch.is_installed("pycryptodomex"):
    print("Installing pycryptodomex...")
    launch.run_pip("install pycryptodomex>=3.18.0", "requirements for pngcrypto")

if not launch.is_installed("passlib"):
    print("Installing passlib...")
    launch.run_pip("install passlib>=1.7.0", "requirements for pngcrypto")
