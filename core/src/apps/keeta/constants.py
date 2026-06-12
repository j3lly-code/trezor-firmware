"""
Keeta Network constants.

Values sourced from Keeta SDK and Ledger reference implementation.
"""

# Chain IDs (from Keeta SDK Config.getDefaultConfig)
# Testnet = 1413829460 (0x544B5734), Mainnet = 21378 (0x5382)
TESTNET_CHAIN_ID = 1413829460
MAINNET_CHAIN_ID = 21378

# Network IDs as bytes (from real testnet blocks)
TESTNET_NETWORK_ID = 0x54455354  # ASCII "TEST"
MAINNET_NETWORK_ID = 0x5382

# Curve order constants (from Ledger params.rs)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Algorithm bytes
ALGO_SECP256K1 = 0x00
ALGO_ED25519 = 0x01
ALGO_NETWORK = 0x02
ALGO_TOKEN = 0x03
ALGO_STORAGE = 0x04
ALGO_SECP256R1 = 0x06
ALGO_MULTISIG = 0x07  # MUST reject in signing

# BIP-32 paths
SLIP44_ID = 8887

# Token cache limits
TOKEN_CACHE_MAX_ENTRIES = 12

# DER parser limits
MAX_BLOCK_SIZE = 128 * 1024  # 128 KB
MAX_CHUNKS = 1024
MAX_DER_DEPTH = 5
OP_BUF_SIZE = 512
MAX_HEADER_SIZE = 6
MAX_HEADER_FIELD_SIZE = 256

# Session timeout for streaming block signing (milliseconds)
SESSION_TIMEOUT_MS = 120_000  # 120 seconds

# Trusted public key for token metadata verification (from Ledger constants.rs)
# Format: 65-byte uncompressed secp256k1 public key (0x04 prefix)
# TODO: Replace with actual trusted key from Keeta before production
TRUSTED_TOKEN_KEY = bytes.fromhex(
    "04"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
)

# Operation type tags (DER context tags)
OP_SEND = 0xA0
OP_SET_REP = 0xA1
OP_SET_INFO = 0xA2
OP_MODIFY_PERMISSIONS = 0xA3
OP_CREATE_IDENTIFIER = 0xA4
OP_TOKEN_ADMIN_SUPPLY = 0xA5
OP_TOKEN_ADMIN_MODIFY_BALANCE = 0xA6
OP_RECEIVE = 0xA7
OP_MANAGE_CERTIFICATE = 0xA8

# Operation type names for display
OP_NAMES = {
    0xA0: "Send",
    0xA1: "Set Representative",
    0xA2: "Set Info",
    0xA3: "Modify Permissions",
    0xA4: "Create Identifier",
    0xA5: "Token Admin Supply",
    0xA6: "Token Admin Modify Balance",
    0xA7: "Receive",
    0xA8: "Manage Certificate",
}

# Version info
KEETA_VERSION_MAJOR = 1
KEETA_VERSION_MINOR = 0
KEETA_VERSION_PATCH = 0
KEETA_VERSION_FLAGS = 0  # bit 0 = blind signing supported, etc.

# Rejected operation tags
REJECTED_OP_TAGS = {0xA9, 0xAA}  # Unassigned, must reject

# DER tags
TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_UTF8_STRING = 0x0C
TAG_GENERALIZED_TIME = 0x18
TAG_CONTEXT_0 = 0xA0  # first operation tag / V2 wrapper might use specific tags
