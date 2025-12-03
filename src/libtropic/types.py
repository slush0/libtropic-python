"""
Data types for libtropic Python bindings.

Provides dataclasses and typed structures matching the C SDK.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple

from .enums import EccCurve, EccKeyOrigin


# =============================================================================
# Constants
# =============================================================================

# Key lengths
X25519_KEY_LEN = 32
P256_PUBKEY_LEN = 64
ED25519_PUBKEY_LEN = 32
PRIVKEY_LEN = 32
SIGNATURE_LEN = 64

# Slot limits
ECC_SLOT_MAX = 31
PAIRING_KEY_SLOT_MAX = 3
MCOUNTER_MAX = 15
MAC_AND_DESTROY_SLOT_MAX = 127
R_MEM_DATA_SLOT_MAX = 511

# Size limits
MCOUNTER_VALUE_MAX = 0xFFFFFFFE
MAC_AND_DESTROY_DATA_SIZE = 32
RANDOM_VALUE_MAX_LEN = 255
PING_LEN_MAX = 255
EDDSA_MSG_LEN_MAX = 4096

# Firmware update limits
MUTABLE_FW_UPDATE_SIZE_MAX_ABAB = 25600
MUTABLE_FW_UPDATE_SIZE_MAX_ACAB = 30720


# =============================================================================
# Device Information Types
# =============================================================================

@dataclass
class ChipId:
    """
    TROPIC01 chip identification data.

    Contains device serial number, version info, and manufacturing data.
    Maps to lt_chip_id_t from C SDK.
    """
    chip_id_version: bytes         # 4 bytes - CHIP_ID structure version
    fl_chip_info: bytes            # 16 bytes - Factory level test info
    func_test_info: bytes          # 16 bytes - Manufacturing test info
    silicon_rev: str               # 4 chars - Silicon revision (e.g., "ACAB")
    package_type_id: int           # Package type identifier
    provisioning_version: int      # Provisioning info version
    fab_id: int                    # Fabrication facility ID
    short_part_number: int         # Short part number
    provisioning_date: bytes       # 4 bytes - Provisioning date
    hsm_version: bytes             # 4 bytes - HSM HW/FW/SW version
    programmer_version: bytes      # 4 bytes - Programmer version
    serial_number: bytes           # Full serial number data
    part_number: str               # Full part number string
    prov_template_version: Tuple[int, int]  # (major, minor)
    prov_template_tag: bytes       # 4 bytes
    prov_spec_version: Tuple[int, int]      # (major, minor)
    prov_spec_tag: bytes           # 4 bytes
    batch_id: bytes                # 4 bytes


@dataclass
class FirmwareVersion:
    """Firmware version information."""
    major: int
    minor: int
    patch: int
    build: int = 0

    def __str__(self) -> str:
        if self.build:
            return f"{self.major}.{self.minor}.{self.patch}.{self.build}"
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass
class FirmwareHeader:
    """
    Firmware bank header information.

    Structure varies based on bootloader version.
    """
    fw_type: int                   # Firmware type identifier
    version: int                   # Firmware version (packed)
    size: int                      # Firmware size in bytes
    git_hash: bytes                # Git commit hash
    content_hash: bytes            # SHA256 hash of firmware content
    header_version: int = 1        # Header format version
    pair_version: Optional[int] = None  # Paired version (boot v2 only)


# =============================================================================
# Certificate Types
# =============================================================================

@dataclass
class CertificateStore:
    """
    X.509 certificate chain from device.

    Maps to lt_cert_store_t from C SDK.
    """
    device_cert: bytes             # Device certificate (DER encoded)
    intermediate_cert: bytes       # Intermediate CA certificate
    tropic01_cert: bytes           # TROPIC01 certificate
    root_cert: bytes               # Root CA certificate

    @property
    def certificates(self) -> List[bytes]:
        """Return all certificates as a list."""
        return [
            self.device_cert,
            self.intermediate_cert,
            self.tropic01_cert,
            self.root_cert
        ]


# =============================================================================
# ECC Key Types
# =============================================================================

@dataclass
class EccKeyInfo:
    """
    ECC key information returned from key read operations.

    Contains the public key and metadata about the key.
    """
    public_key: bytes              # Public key bytes (32B for Ed25519, 64B for P256)
    curve: EccCurve                # Curve type
    origin: EccKeyOrigin           # How key was created (generated vs stored)

    @property
    def key_length(self) -> int:
        """Get expected key length based on curve."""
        if self.curve == EccCurve.ED25519:
            return ED25519_PUBKEY_LEN
        return P256_PUBKEY_LEN


# =============================================================================
# Configuration Types
# =============================================================================

@dataclass
class DeviceConfig:
    """
    Device configuration object collection.

    Holds all R-Config or I-Config values.
    Maps to lt_config_t from C SDK.
    """
    start_up: int = 0xFFFFFFFF
    sensors: int = 0xFFFFFFFF
    debug: int = 0xFFFFFFFF
    gpo: int = 0xFFFFFFFF
    sleep_mode: int = 0xFFFFFFFF
    uap_pairing_key_write: int = 0xFFFFFFFF
    uap_pairing_key_read: int = 0xFFFFFFFF
    uap_pairing_key_invalidate: int = 0xFFFFFFFF
    uap_r_config_write_erase: int = 0xFFFFFFFF
    uap_r_config_read: int = 0xFFFFFFFF
    uap_i_config_write: int = 0xFFFFFFFF
    uap_i_config_read: int = 0xFFFFFFFF
    uap_ping: int = 0xFFFFFFFF
    uap_r_mem_data_write: int = 0xFFFFFFFF
    uap_r_mem_data_read: int = 0xFFFFFFFF
    uap_r_mem_data_erase: int = 0xFFFFFFFF
    uap_random_value_get: int = 0xFFFFFFFF
    uap_ecc_key_generate: int = 0xFFFFFFFF
    uap_ecc_key_store: int = 0xFFFFFFFF
    uap_ecc_key_read: int = 0xFFFFFFFF
    uap_ecc_key_erase: int = 0xFFFFFFFF
    uap_ecdsa_sign: int = 0xFFFFFFFF
    uap_eddsa_sign: int = 0xFFFFFFFF
    uap_mcounter_init: int = 0xFFFFFFFF
    uap_mcounter_get: int = 0xFFFFFFFF
    uap_mcounter_update: int = 0xFFFFFFFF
    uap_mac_and_destroy: int = 0xFFFFFFFF


# =============================================================================
# Serial Number Types
# =============================================================================

@dataclass
class SerialNumber:
    """
    Parsed serial number structure.

    Maps to lt_ser_num_t from C SDK.
    """
    sn: bytes                      # 2 bytes - Serial number
    fab_data: bytes                # 4 bytes - Fabrication data
    fab_date: bytes                # 4 bytes - Fabrication date
    lot_id: bytes                  # 4 bytes - Lot ID
    wafer_id: bytes                # 1 byte - Wafer ID
    x_coord: bytes                 # 2 bytes - X coordinate on wafer
    y_coord: bytes                 # 2 bytes - Y coordinate on wafer
