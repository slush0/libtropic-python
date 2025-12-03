"""
Internal protocol implementation for TROPIC01 communication.

This module provides the L1 (physical) and L2 (data link) layer implementations
for communicating with the TROPIC01 secure element.

WARNING: This is a private module. Do not import directly from application code.
"""

from .constants import (
    # L1 constants
    L1_CHIP_MODE_READY,
    L1_CHIP_MODE_ALARM,
    L1_CHIP_MODE_STARTUP,
    L1_GET_RESPONSE_REQ_ID,
    L1_READ_MAX_TRIES,
    L1_READ_RETRY_DELAY_MS,
    L1_TIMEOUT_MS_DEFAULT,
    L1_LEN_MAX,
    # L2 constants
    L2_STATUS_REQUEST_OK,
    L2_STATUS_RESULT_OK,
    L2_STATUS_REQUEST_CONT,
    L2_STATUS_RESULT_CONT,
    L2_STATUS_RESP_DISABLED,
    L2_STATUS_HSK_ERR,
    L2_STATUS_NO_SESSION,
    L2_STATUS_TAG_ERR,
    L2_STATUS_CRC_ERR,
    L2_STATUS_UNKNOWN_ERR,
    L2_STATUS_GEN_ERR,
    L2_STATUS_NO_RESP,
    # L2 Request IDs
    L2_GET_INFO_REQ_ID,
    L2_HANDSHAKE_REQ_ID,
    L2_ENCRYPTED_CMD_REQ_ID,
    L2_SESSION_ABORT_REQ_ID,
    L2_RESEND_REQ_ID,
    L2_SLEEP_REQ_ID,
    L2_STARTUP_REQ_ID,
    L2_GET_LOG_REQ_ID,
    # Object IDs
    L2_GET_INFO_OBJECT_ID_X509_CERT,
    L2_GET_INFO_OBJECT_ID_CHIP_ID,
    L2_GET_INFO_OBJECT_ID_RISCV_FW_VER,
    L2_GET_INFO_OBJECT_ID_SPECT_FW_VER,
    L2_GET_INFO_OBJECT_ID_FW_BANK,
    # Startup IDs
    STARTUP_ID_REBOOT,
    STARTUP_ID_MAINTENANCE,
    # Sleep kinds
    SLEEP_KIND_SLEEP,
    # Sizes
    L2_MAX_FRAME_SIZE,
    L2_CHUNK_MAX_DATA_SIZE,
    REBOOT_DELAY_MS,
)
from .crc16 import crc16, add_crc, verify_crc
from .l1 import L1Layer
from .l2 import L2Layer, L2FrameStatus

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
    "STARTUP_ID_REBOOT",
    "STARTUP_ID_MAINTENANCE",
    "SLEEP_KIND_SLEEP",
    "L2_MAX_FRAME_SIZE",
    "L2_CHUNK_MAX_DATA_SIZE",
    "REBOOT_DELAY_MS",
    # CRC
    "crc16",
    "add_crc",
    "verify_crc",
    # Layers
    "L1Layer",
    "L2Layer",
    "L2FrameStatus",
]

