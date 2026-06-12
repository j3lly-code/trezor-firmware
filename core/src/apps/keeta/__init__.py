CURVE = "secp256k1"  # primary curve; ed25519 and secp256r1 also supported explicitly
SLIP44_ID = 8887
PATTERNS = (
    "m/44'/coin_type'",
    "m/44'/coin_type'/account'/0'/0'",  # supports variable account indices
)
