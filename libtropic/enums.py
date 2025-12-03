"""
Enumerations for libtropic Python bindings.

Maps to C SDK enum types from libtropic_common.h and related headers.
"""

from enum import IntEnum, auto


class ReturnCode(IntEnum):
    """
    Return codes from libtropic operations.

    Maps to lt_ret_t from C SDK.
    """
    OK = 0
    FAIL = 1
    HOST_NO_SESSION = 2
    PARAM_ERR = 3
    CRYPTO_ERR = 4
    APP_FW_TOO_NEW = 5
    REBOOT_UNSUCCESSFUL = 6

    # L1 layer errors
    L1_SPI_ERROR = 7
    L1_DATA_LEN_ERROR = 8
    L1_CHIP_STARTUP_MODE = 9
    L1_CHIP_ALARM_MODE = 10
    L1_CHIP_BUSY = 11
    L1_INT_TIMEOUT = 12

    # L3 layer results
    L3_SLOT_NOT_EMPTY = 13
    L3_SLOT_EXPIRED = 14
    L3_INVALID_KEY = 15
    L3_UPDATE_ERR = 16
    L3_COUNTER_INVALID = 17
    L3_SLOT_EMPTY = 18
    L3_SLOT_INVALID = 19
    L3_OK = 20
    L3_FAIL = 21
    L3_UNAUTHORIZED = 22
    L3_INVALID_CMD = 23
    L3_HARDWARE_FAIL = 24
    L3_DATA_LEN_ERROR = 25
    L3_RES_SIZE_ERROR = 26
    L3_BUFFER_TOO_SMALL = 27
    L3_R_MEM_DATA_READ_SLOT_EMPTY = 28
    L3_RESULT_UNKNOWN = 29

    # L2 layer status
    L2_REQ_CONT = 30
    L2_RES_CONT = 31
    L2_RESP_DISABLED = 32
    L2_HSK_ERR = 33
    L2_NO_SESSION = 34
    L2_TAG_ERR = 35
    L2_CRC_ERR = 36
    L2_GEN_ERR = 37
    L2_NO_RESP = 38
    L2_UNKNOWN_REQ = 39
    L2_IN_CRC_ERR = 40
    L2_RSP_LEN_ERROR = 41
    L2_STATUS_UNKNOWN = 42

    # Certificate errors
    CERT_STORE_INVALID = 43
    CERT_UNSUPPORTED = 44
    CERT_ITEM_NOT_FOUND = 45
    NONCE_OVERFLOW = 46


class DeviceMode(IntEnum):
    """
    TROPIC01 operating modes.

    Maps to lt_tr01_mode_t from C SDK.
    """
    MAINTENANCE = 0   # Bootloader mode, accepts L2 requests
    APPLICATION = 1   # Running app firmware, accepts L2/L3 commands
    ALARM = 2         # Alarm mode (security event triggered)


class StartupMode(IntEnum):
    """
    Reboot/startup mode selection.

    Maps to lt_startup_id_t from C SDK.
    """
    REBOOT = 0x01              # Normal reboot to application mode
    MAINTENANCE_REBOOT = 0x03  # Reboot to maintenance/bootloader mode


class EccCurve(IntEnum):
    """
    Elliptic curve types for ECC operations.

    Maps to lt_ecc_curve_type_t from C SDK.
    """
    P256 = 1       # NIST P-256 (secp256r1)
    ED25519 = 2    # Ed25519 (Curve25519)


class EccKeyOrigin(IntEnum):
    """
    Origin of an ECC key (how it was created).

    Maps to lt_ecc_key_origin_t from C SDK.
    """
    GENERATED = 1  # Key was generated on-chip
    STORED = 2     # Key was imported/stored externally


class FirmwareBank(IntEnum):
    """
    Firmware bank identifiers for update operations.

    Maps to lt_bank_id_t from C SDK.
    """
    FW1 = 1        # Application firmware bank 1
    FW2 = 2        # Application firmware bank 2
    SPECT1 = 17    # SPECT coprocessor firmware bank 1
    SPECT2 = 18    # SPECT coprocessor firmware bank 2


class PairingKeySlot(IntEnum):
    """
    Pairing key slot indices (0-3).

    Maps to lt_pkey_index_t from C SDK.
    """
    SLOT_0 = 0
    SLOT_1 = 1
    SLOT_2 = 2
    SLOT_3 = 3


class EccSlot(IntEnum):
    """
    ECC key slot indices (0-31).

    Maps to lt_ecc_slot_t from C SDK.
    """
    SLOT_0 = 0
    SLOT_1 = 1
    SLOT_2 = 2
    SLOT_3 = 3
    SLOT_4 = 4
    SLOT_5 = 5
    SLOT_6 = 6
    SLOT_7 = 7
    SLOT_8 = 8
    SLOT_9 = 9
    SLOT_10 = 10
    SLOT_11 = 11
    SLOT_12 = 12
    SLOT_13 = 13
    SLOT_14 = 14
    SLOT_15 = 15
    SLOT_16 = 16
    SLOT_17 = 17
    SLOT_18 = 18
    SLOT_19 = 19
    SLOT_20 = 20
    SLOT_21 = 21
    SLOT_22 = 22
    SLOT_23 = 23
    SLOT_24 = 24
    SLOT_25 = 25
    SLOT_26 = 26
    SLOT_27 = 27
    SLOT_28 = 28
    SLOT_29 = 29
    SLOT_30 = 30
    SLOT_31 = 31


class McounterIndex(IntEnum):
    """
    Monotonic counter indices (0-15).

    Maps to lt_mcounter_index_t from C SDK.
    """
    COUNTER_0 = 0
    COUNTER_1 = 1
    COUNTER_2 = 2
    COUNTER_3 = 3
    COUNTER_4 = 4
    COUNTER_5 = 5
    COUNTER_6 = 6
    COUNTER_7 = 7
    COUNTER_8 = 8
    COUNTER_9 = 9
    COUNTER_10 = 10
    COUNTER_11 = 11
    COUNTER_12 = 12
    COUNTER_13 = 13
    COUNTER_14 = 14
    COUNTER_15 = 15


class MacAndDestroySlot(IntEnum):
    """
    MAC-and-Destroy slot indices (0-127).

    Maps to lt_mac_and_destroy_slot_t from C SDK.
    Only first 32 shown; use integer 0-127 for higher slots.
    """
    SLOT_0 = 0
    SLOT_1 = 1
    SLOT_2 = 2
    SLOT_3 = 3
    SLOT_4 = 4
    SLOT_5 = 5
    SLOT_6 = 6
    SLOT_7 = 7
    SLOT_8 = 8
    SLOT_9 = 9
    SLOT_10 = 10
    SLOT_11 = 11
    SLOT_12 = 12
    SLOT_13 = 13
    SLOT_14 = 14
    SLOT_15 = 15
    # ... slots 16-127 can be accessed as integers


class ConfigAddress(IntEnum):
    """
    Configuration object addresses for R-Config and I-Config.

    Maps to lt_config_obj_addr_t from C SDK.
    """
    START_UP = 0x0000
    SENSORS = 0x0004
    DEBUG = 0x0008
    GPO = 0x000C
    SLEEP_MODE = 0x0010
    UAP_PAIRING_KEY_WRITE = 0x0100
    UAP_PAIRING_KEY_READ = 0x0104
    UAP_PAIRING_KEY_INVALIDATE = 0x0108
    UAP_R_CONFIG_WRITE_ERASE = 0x010C
    UAP_R_CONFIG_READ = 0x0110
    UAP_I_CONFIG_WRITE = 0x0114
    UAP_I_CONFIG_READ = 0x0118
    UAP_PING = 0x011C
    UAP_R_MEM_DATA_WRITE = 0x0120
    UAP_R_MEM_DATA_READ = 0x0124
    UAP_R_MEM_DATA_ERASE = 0x0128
    UAP_RANDOM_VALUE_GET = 0x012C
    UAP_ECC_KEY_GENERATE = 0x0130
    UAP_ECC_KEY_STORE = 0x0134
    UAP_ECC_KEY_READ = 0x0138
    UAP_ECC_KEY_ERASE = 0x013C
    UAP_ECDSA_SIGN = 0x0140
    UAP_EDDSA_SIGN = 0x0144
    UAP_MCOUNTER_INIT = 0x0148
    UAP_MCOUNTER_GET = 0x014C
    UAP_MCOUNTER_UPDATE = 0x0150
    UAP_MAC_AND_DESTROY = 0x0154


class CertKind(IntEnum):
    """
    Certificate types in the certificate store.

    Maps to lt_cert_kind_t from C SDK.
    """
    DEVICE = 0       # Device certificate
    INTERMEDIATE = 1 # Intermediate CA certificate (XXXX)
    TROPIC01 = 2     # TROPIC01 certificate
    ROOT = 3         # Root CA certificate
