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

