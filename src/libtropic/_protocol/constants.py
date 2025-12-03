"""
Protocol constants for TROPIC01 communication.

These values are derived from the libtropic C library and the TROPIC01 datasheet.
"""

# =============================================================================
# L1 (Physical Layer) Constants
# =============================================================================

# Chip status byte bit flags
L1_CHIP_MODE_READY = 0x01    # Chip is ready to accept requests
L1_CHIP_MODE_ALARM = 0x02    # Chip is in ALARM mode
L1_CHIP_MODE_STARTUP = 0x04  # Chip is in STARTUP (maintenance) mode

# Request ID to read response from chip
L1_GET_RESPONSE_REQ_ID = 0xAA

# Polling configuration
L1_READ_MAX_TRIES = 50       # Max number of read retries when chip is busy
L1_READ_RETRY_DELAY_MS = 25  # Delay between read retries (ms)

# Timeout configuration
L1_TIMEOUT_MS_MIN = 5
L1_TIMEOUT_MS_DEFAULT = 70
L1_TIMEOUT_MS_MAX = 150

# Frame sizes
L1_CHIP_STATUS_SIZE = 1
L2_MAX_FRAME_SIZE = 256  # STATUS + LEN + DATA(252) + CRC(2)
L1_LEN_MAX = L1_CHIP_STATUS_SIZE + L2_MAX_FRAME_SIZE  # 257 bytes max


# =============================================================================
# L2 (Data Link Layer) Constants
# =============================================================================

# Frame offsets for L2 requests
L2_REQ_ID_OFFSET = 0
L2_REQ_LEN_OFFSET = 1
L2_REQ_DATA_OFFSET = 2

# Frame offsets for L2 responses (after chip_status byte)
L2_CHIP_STATUS_OFFSET = 0
L2_STATUS_OFFSET = 1
L2_RSP_LEN_OFFSET = 2
L2_RSP_DATA_OFFSET = 3

# Field sizes
L2_REQ_ID_SIZE = 1
L2_REQ_RSP_LEN_SIZE = 1
L2_REQ_RSP_CRC_SIZE = 2
L2_STATUS_SIZE = 1
L2_CHUNK_MAX_DATA_SIZE = 252

# L2 Response STATUS byte values
L2_STATUS_REQUEST_OK = 0x01      # Request executed successfully
L2_STATUS_RESULT_OK = 0x02       # Result ready
L2_STATUS_REQUEST_CONT = 0x03    # More request chunks expected
L2_STATUS_RESULT_CONT = 0x04     # More result chunks to read
L2_STATUS_RESP_DISABLED = 0x78   # Request disabled
L2_STATUS_HSK_ERR = 0x79         # Handshake error
L2_STATUS_NO_SESSION = 0x7A      # No active session
L2_STATUS_TAG_ERR = 0x7B         # Authentication tag error
L2_STATUS_CRC_ERR = 0x7C         # CRC error
L2_STATUS_UNKNOWN_ERR = 0x7E     # Unknown request
L2_STATUS_GEN_ERR = 0x7F         # General error
L2_STATUS_NO_RESP = 0xFF         # No response available


# =============================================================================
# L2 Request IDs
# =============================================================================

L2_GET_INFO_REQ_ID = 0x01
L2_HANDSHAKE_REQ_ID = 0x02
L2_ENCRYPTED_CMD_REQ_ID = 0x04
L2_SESSION_ABORT_REQ_ID = 0x08
L2_RESEND_REQ_ID = 0x10
L2_SLEEP_REQ_ID = 0x20
L2_GET_LOG_REQ_ID = 0xA2
L2_STARTUP_REQ_ID = 0xB3

# Firmware update L2 request IDs (maintenance mode only, ACAB silicon)
L2_MUTABLE_FW_UPDATE_REQ_ID = 0xB0            # Start authenticated FW update
L2_MUTABLE_FW_UPDATE_DATA_REQ_ID = 0xB1       # Send FW data chunks


# =============================================================================
# GET_INFO Object IDs
# =============================================================================

L2_GET_INFO_OBJECT_ID_X509_CERT = 0x00
L2_GET_INFO_OBJECT_ID_CHIP_ID = 0x01
L2_GET_INFO_OBJECT_ID_RISCV_FW_VER = 0x02
L2_GET_INFO_OBJECT_ID_SPECT_FW_VER = 0x04
L2_GET_INFO_OBJECT_ID_FW_BANK = 0xB0

# Block indexes for X509 certificate (returned in 128-byte chunks)
L2_GET_INFO_BLOCK_INDEX_0 = 0x00  # Bytes 0-127
L2_GET_INFO_BLOCK_INDEX_1 = 0x01  # Bytes 128-255
L2_GET_INFO_BLOCK_INDEX_2 = 0x02  # Bytes 256-383
L2_GET_INFO_BLOCK_INDEX_3 = 0x03  # Bytes 384-511


# =============================================================================
# Handshake Constants
# =============================================================================

L2_HANDSHAKE_REQ_LEN = 33    # 32B ephemeral pubkey + 1B slot index
L2_HANDSHAKE_RSP_LEN = 48    # 32B device ephemeral pubkey + 16B auth tag

# Offsets within handshake response data
HANDSHAKE_RSP_ET_PUB_OFFSET = 0   # Device ephemeral public key
HANDSHAKE_RSP_ET_PUB_SIZE = 32
HANDSHAKE_RSP_T_AUTH_OFFSET = 32  # Authentication tag
HANDSHAKE_RSP_T_AUTH_SIZE = 16


# =============================================================================
# Startup/Reboot IDs
# =============================================================================

STARTUP_ID_REBOOT = 0x01       # Normal reboot to application mode
STARTUP_ID_MAINTENANCE = 0x03  # Reboot to maintenance/startup mode


# =============================================================================
# Sleep Kinds
# =============================================================================

SLEEP_KIND_SLEEP = 0x05  # Basic sleep mode


# =============================================================================
# Timing Constants
# =============================================================================

REBOOT_DELAY_MS = 250  # Delay after reboot command


# =============================================================================
# Data Sizes
# =============================================================================

# GET_INFO response sizes
GET_INFO_CHIP_ID_SIZE = 128
GET_INFO_RISCV_FW_SIZE = 4
GET_INFO_SPECT_FW_SIZE = 4
GET_INFO_FW_HEADER_SIZE = 52
GET_INFO_CERT_CHUNK_SIZE = 128

# X25519 key sizes
X25519_KEY_LEN = 32

# AES-GCM sizes
AES256_KEY_LEN = 32
AESGCM_TAG_SIZE = 16
AESGCM_IV_SIZE = 12

# L3 sizes
L3_SIZE_SIZE = 2
L3_TAG_SIZE = 16
L3_CMD_ID_SIZE = 1
L3_RESULT_SIZE = 1
L3_IV_SIZE = 12

# Maximum L3 payload sizes
L3_CMD_DATA_MAX_SIZE = 4096
L3_RES_DATA_MAX_SIZE = 4096


# =============================================================================
# L3 Command IDs
# =============================================================================

L3_CMD_PING = 0x01

L3_CMD_PAIRING_KEY_WRITE = 0x10
L3_CMD_PAIRING_KEY_READ = 0x11
L3_CMD_PAIRING_KEY_INVALIDATE = 0x12

L3_CMD_R_CONFIG_WRITE = 0x20
L3_CMD_R_CONFIG_READ = 0x21
L3_CMD_R_CONFIG_ERASE = 0x22

L3_CMD_I_CONFIG_WRITE = 0x30
L3_CMD_I_CONFIG_READ = 0x31

L3_CMD_R_MEM_DATA_WRITE = 0x40
L3_CMD_R_MEM_DATA_READ = 0x41
L3_CMD_R_MEM_DATA_ERASE = 0x42

L3_CMD_RANDOM_VALUE_GET = 0x50

L3_CMD_ECC_KEY_GENERATE = 0x60
L3_CMD_ECC_KEY_STORE = 0x61
L3_CMD_ECC_KEY_READ = 0x62
L3_CMD_ECC_KEY_ERASE = 0x63

L3_CMD_ECDSA_SIGN = 0x70
L3_CMD_EDDSA_SIGN = 0x71

L3_CMD_MCOUNTER_INIT = 0x80
L3_CMD_MCOUNTER_UPDATE = 0x81
L3_CMD_MCOUNTER_GET = 0x82

L3_CMD_MAC_AND_DESTROY = 0x90


# =============================================================================
# L3 Result Codes (from lt_l3_process.h)
# =============================================================================

L3_RESULT_OK = 0xC3              # Command executed successfully
L3_RESULT_FAIL = 0x3C            # General failure
L3_RESULT_UNAUTHORIZED = 0x01    # Operation not permitted (UAP)
L3_RESULT_INVALID_CMD = 0x02     # Invalid command ID
L3_RESULT_SLOT_NOT_EMPTY = 0x10  # Slot already contains data
L3_RESULT_SLOT_EXPIRED = 0x11    # Flash slot has expired
L3_RESULT_INVALID_KEY = 0x12     # Key is invalid or wrong type
L3_RESULT_UPDATE_ERR = 0x13      # Update operation failed
L3_RESULT_COUNTER_INVALID = 0x14 # Counter not initialized or at zero
L3_RESULT_SLOT_EMPTY = 0x15      # Slot is empty
L3_RESULT_SLOT_INVALID = 0x16    # Slot content is invalidated
L3_RESULT_HARDWARE_FAIL = 0x17   # Hardware failure


# =============================================================================
# L3 Command/Response Sizes (from lt_l3_api_structs.h)
# =============================================================================

# Ping
L3_PING_CMD_SIZE_MIN = 1  # CMD_ID only
L3_PING_RES_SIZE_MIN = 1  # RESULT only
L3_PING_DATA_MAX = 4096

# Pairing Key
L3_PAIRING_KEY_WRITE_CMD_SIZE = 36  # CMD_ID + slot(2) + padding(1) + pubkey(32)
L3_PAIRING_KEY_READ_CMD_SIZE = 3    # CMD_ID + slot(2)
L3_PAIRING_KEY_READ_RES_SIZE = 36   # RESULT + padding(3) + pubkey(32)
L3_PAIRING_KEY_INVALIDATE_CMD_SIZE = 3

# R-Config
L3_R_CONFIG_WRITE_CMD_SIZE = 8   # CMD_ID + addr(2) + padding(1) + value(4)
L3_R_CONFIG_READ_CMD_SIZE = 3    # CMD_ID + addr(2)
L3_R_CONFIG_READ_RES_SIZE = 8    # RESULT + padding(3) + value(4)
L3_R_CONFIG_ERASE_CMD_SIZE = 1   # CMD_ID only

# I-Config
L3_I_CONFIG_WRITE_CMD_SIZE = 4   # CMD_ID + addr(2) + bit_index(1)
L3_I_CONFIG_READ_CMD_SIZE = 3    # CMD_ID + addr(2)
L3_I_CONFIG_READ_RES_SIZE = 8    # RESULT + padding(3) + value(4)

# R-Memory Data
L3_R_MEM_DATA_WRITE_CMD_SIZE_MIN = 5   # CMD_ID + slot(2) + padding(1) + min_data(1)
L3_R_MEM_DATA_READ_CMD_SIZE = 3        # CMD_ID + slot(2)
L3_R_MEM_DATA_READ_RES_SIZE_MIN = 4    # RESULT + padding(3)
L3_R_MEM_DATA_READ_PADDING_SIZE = 3
L3_R_MEM_DATA_ERASE_CMD_SIZE = 3       # CMD_ID + slot(2)
L3_R_MEM_DATA_SLOT_MAX = 511
L3_R_MEM_DATA_SIZE_MAX = 444           # Max data per slot (firmware dependent)

# Random
L3_RANDOM_VALUE_GET_CMD_SIZE = 2  # CMD_ID + n_bytes(1)
L3_RANDOM_VALUE_GET_RES_SIZE_MIN = 4  # RESULT + padding(3)
L3_RANDOM_VALUE_GET_MAX_BYTES = 255

# ECC Key
L3_ECC_KEY_GENERATE_CMD_SIZE = 4  # CMD_ID + slot(2) + curve(1)
L3_ECC_KEY_STORE_CMD_SIZE = 48    # CMD_ID + slot(2) + curve(1) + padding(12) + key(32)
L3_ECC_KEY_READ_CMD_SIZE = 3      # CMD_ID + slot(2)
L3_ECC_KEY_READ_RES_SIZE_MIN = 48 # RESULT + curve(1) + origin(1) + padding(13) + pubkey(32)
L3_ECC_KEY_READ_RES_SIZE_MAX = 80 # For P256: padding(13) + pubkey(64)
L3_ECC_KEY_ERASE_CMD_SIZE = 3     # CMD_ID + slot(2)
L3_ECC_SLOT_MAX = 31

# Signing
L3_ECDSA_SIGN_CMD_SIZE = 48       # CMD_ID + slot(2) + padding(13) + hash(32)
L3_ECDSA_SIGN_RES_SIZE = 80       # RESULT + padding(15) + r(32) + s(32)
L3_EDDSA_SIGN_CMD_SIZE_MIN = 16   # CMD_ID + slot(2) + padding(13)
L3_EDDSA_SIGN_CMD_MSG_MAX = 4096
L3_EDDSA_SIGN_RES_SIZE = 80       # RESULT + padding(15) + r(32) + s(32)

# Monotonic Counter
L3_MCOUNTER_INIT_CMD_SIZE = 8     # CMD_ID + index(2) + padding(1) + value(4)
L3_MCOUNTER_UPDATE_CMD_SIZE = 3   # CMD_ID + index(2)
L3_MCOUNTER_GET_CMD_SIZE = 3      # CMD_ID + index(2)
L3_MCOUNTER_GET_RES_SIZE = 8      # RESULT + padding(3) + value(4)
L3_MCOUNTER_INDEX_MAX = 15

# MAC-and-Destroy
L3_MAC_AND_DESTROY_CMD_SIZE = 36  # CMD_ID + slot(2) + padding(1) + data_in(32)
L3_MAC_AND_DESTROY_RES_SIZE = 36  # RESULT + padding(3) + data_out(32)
L3_MAC_AND_DESTROY_SLOT_MAX = 127
L3_MAC_AND_DESTROY_DATA_SIZE = 32

# ECC Curve types
L3_ECC_CURVE_P256 = 0x01
L3_ECC_CURVE_ED25519 = 0x02

# ECC Key origins
L3_ECC_KEY_ORIGIN_GENERATED = 0x01
L3_ECC_KEY_ORIGIN_STORED = 0x02

# ECC Public key sizes
L3_ECC_PUBKEY_P256_SIZE = 64
L3_ECC_PUBKEY_ED25519_SIZE = 32
L3_ECC_PRIVKEY_SIZE = 32


# =============================================================================
# Firmware Update Constants (L2 level, maintenance mode only, ACAB silicon)
# =============================================================================

# ACAB authenticated firmware update header size
L2_MUTABLE_FW_UPDATE_HEADER_SIZE = 0x68      # 104 bytes: signature(64) + hash(32) + header(8)

# Maximum firmware size for ACAB silicon
MUTABLE_FW_UPDATE_SIZE_MAX = 30720
