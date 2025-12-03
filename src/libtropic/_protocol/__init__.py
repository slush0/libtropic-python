"""
Internal protocol implementation for TROPIC01 communication.

This module provides the L1 (physical) and L2 (data link) layer implementations
for communicating with the TROPIC01 secure element.

WARNING: This is a private module. Do not import directly from application code.
"""

from .constants import (
    AES256_KEY_LEN,
    AESGCM_IV_SIZE,
    AESGCM_TAG_SIZE,
    HANDSHAKE_RSP_ET_PUB_OFFSET,
    HANDSHAKE_RSP_ET_PUB_SIZE,
    HANDSHAKE_RSP_T_AUTH_OFFSET,
    HANDSHAKE_RSP_T_AUTH_SIZE,
    L1_CHIP_MODE_ALARM,
    # L1 constants
    L1_CHIP_MODE_READY,
    L1_CHIP_MODE_STARTUP,
    L1_GET_RESPONSE_REQ_ID,
    L1_LEN_MAX,
    L1_READ_MAX_TRIES,
    L1_READ_RETRY_DELAY_MS,
    L1_TIMEOUT_MS_DEFAULT,
    L2_CHUNK_MAX_DATA_SIZE,
    L2_ENCRYPTED_CMD_REQ_ID,
    L2_GET_INFO_OBJECT_ID_CHIP_ID,
    L2_GET_INFO_OBJECT_ID_FW_BANK,
    L2_GET_INFO_OBJECT_ID_RISCV_FW_VER,
    L2_GET_INFO_OBJECT_ID_SPECT_FW_VER,
    # Object IDs
    L2_GET_INFO_OBJECT_ID_X509_CERT,
    # L2 Request IDs
    L2_GET_INFO_REQ_ID,
    L2_GET_LOG_REQ_ID,
    L2_HANDSHAKE_REQ_ID,
    # Handshake constants
    L2_HANDSHAKE_REQ_LEN,
    L2_HANDSHAKE_RSP_LEN,
    # Sizes
    L2_MAX_FRAME_SIZE,
    L2_RESEND_REQ_ID,
    L2_SESSION_ABORT_REQ_ID,
    L2_SLEEP_REQ_ID,
    L2_STARTUP_REQ_ID,
    L2_STATUS_CRC_ERR,
    L2_STATUS_GEN_ERR,
    L2_STATUS_HSK_ERR,
    L2_STATUS_NO_RESP,
    L2_STATUS_NO_SESSION,
    L2_STATUS_REQUEST_CONT,
    # L2 constants
    L2_STATUS_REQUEST_OK,
    L2_STATUS_RESP_DISABLED,
    L2_STATUS_RESULT_CONT,
    L2_STATUS_RESULT_OK,
    L2_STATUS_TAG_ERR,
    L2_STATUS_UNKNOWN_ERR,
    REBOOT_DELAY_MS,
    # Sleep kinds
    SLEEP_KIND_SLEEP,
    STARTUP_ID_MAINTENANCE,
    # Startup IDs
    STARTUP_ID_REBOOT,
    X25519_KEY_LEN,
)
from .crc16 import add_crc, crc16, verify_crc
from .l1 import L1Layer
from .l2 import L2FrameStatus, L2Layer
from .l3 import (
    L3Error,
    L3NonceOverflowError,
    L3ResponseSizeError,
    L3ResultError,
    decrypt_response,
    encrypt_command,
    increment_iv,
    result_code_to_exception,
)

__all__ = [
    # Constants
    "L1_CHIP_MODE_READY",
    "L1_CHIP_MODE_ALARM",
    "L1_CHIP_MODE_STARTUP",
    "L1_GET_RESPONSE_REQ_ID",
    "L1_READ_MAX_TRIES",
    "L1_READ_RETRY_DELAY_MS",
    "L1_TIMEOUT_MS_DEFAULT",
    "L1_LEN_MAX",
    "L2_STATUS_REQUEST_OK",
    "L2_STATUS_RESULT_OK",
    "L2_STATUS_REQUEST_CONT",
    "L2_STATUS_RESULT_CONT",
    "L2_STATUS_RESP_DISABLED",
    "L2_STATUS_HSK_ERR",
    "L2_STATUS_NO_SESSION",
    "L2_STATUS_TAG_ERR",
    "L2_STATUS_CRC_ERR",
    "L2_STATUS_UNKNOWN_ERR",
    "L2_STATUS_GEN_ERR",
    "L2_STATUS_NO_RESP",
    "L2_GET_INFO_REQ_ID",
    "L2_HANDSHAKE_REQ_ID",
    "L2_ENCRYPTED_CMD_REQ_ID",
    "L2_SESSION_ABORT_REQ_ID",
    "L2_RESEND_REQ_ID",
    "L2_SLEEP_REQ_ID",
    "L2_STARTUP_REQ_ID",
    "L2_GET_LOG_REQ_ID",
    "L2_GET_INFO_OBJECT_ID_X509_CERT",
    "L2_GET_INFO_OBJECT_ID_CHIP_ID",
    "L2_GET_INFO_OBJECT_ID_RISCV_FW_VER",
    "L2_GET_INFO_OBJECT_ID_SPECT_FW_VER",
    "L2_GET_INFO_OBJECT_ID_FW_BANK",
    "L2_HANDSHAKE_REQ_LEN",
    "L2_HANDSHAKE_RSP_LEN",
    "HANDSHAKE_RSP_ET_PUB_OFFSET",
    "HANDSHAKE_RSP_ET_PUB_SIZE",
    "HANDSHAKE_RSP_T_AUTH_OFFSET",
    "HANDSHAKE_RSP_T_AUTH_SIZE",
    "STARTUP_ID_REBOOT",
    "STARTUP_ID_MAINTENANCE",
    "SLEEP_KIND_SLEEP",
    "L2_MAX_FRAME_SIZE",
    "L2_CHUNK_MAX_DATA_SIZE",
    "REBOOT_DELAY_MS",
    "X25519_KEY_LEN",
    "AES256_KEY_LEN",
    "AESGCM_TAG_SIZE",
    "AESGCM_IV_SIZE",
    # CRC
    "crc16",
    "add_crc",
    "verify_crc",
    # Layers
    "L1Layer",
    "L2Layer",
    "L2FrameStatus",
    # L3 functions
    "L3Error",
    "L3NonceOverflowError",
    "L3ResponseSizeError",
    "L3ResultError",
    "encrypt_command",
    "decrypt_response",
    "increment_iv",
    "result_code_to_exception",
]
