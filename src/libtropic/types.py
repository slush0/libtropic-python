"""
Data types for libtropic Python bindings.

Provides dataclasses and typed structures matching the C SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .enums import ConfigAddress

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
PING_LEN_MAX = 4096
EDDSA_MSG_LEN_MAX = 4096

# Firmware update limits (ACAB silicon)
MUTABLE_FW_UPDATE_SIZE_MAX = 30720


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
    prov_template_version: tuple[int, int]  # (major, minor)
    prov_template_tag: bytes       # 4 bytes
    prov_spec_version: tuple[int, int]      # (major, minor)
    prov_spec_tag: bytes           # 4 bytes
    batch_id: bytes                # 4 bytes

    def __str__(self) -> str:
        """
        Pretty-print chip identification info.

        Maps to: lt_print_chip_id()
        """
        # Decode package type
        pkg_types = {
            0x0000: "Bare silicon die",
            0x0001: "QFN32, 4x4mm",
        }
        pkg_str = pkg_types.get(self.package_type_id, "Unknown")

        # Decode fab ID
        fab_ids = {
            0x001: "Tropic Square Lab",
            0x002: "EPS Global - Brno",
        }
        fab_str = fab_ids.get(self.fab_id, "Unknown")

        # FL test status
        fl_status = "PASSED" if self.fl_chip_info[0] == 0x01 else "N/A"
        func_status = "PASSED" if self.func_test_info[0] == 0x01 else "N/A"

        return (
            f"ChipId:\n"
            f"  CHIP_ID version      = 0x{self.chip_id_version.hex()}\n"
            f"  FL_CHIP_INFO         = 0x{self.fl_chip_info.hex()} ({fl_status})\n"
            f"  MAN_FUNC_TEST        = 0x{self.func_test_info.hex()} ({func_status})\n"
            f"  Silicon revision     = {self.silicon_rev}\n"
            f"  Package ID           = 0x{self.package_type_id:04X} ({pkg_str})\n"
            f"  Prov info version    = 0x{self.provisioning_version:02X}\n"
            f"  Fab ID               = 0x{self.fab_id:03X} ({fab_str})\n"
            f"  P/N ID (short)       = 0x{self.short_part_number:03X}\n"
            f"  Prov date            = 0x{self.provisioning_date.hex()}\n"
            f"  HSM HW/FW/SW ver     = 0x{self.hsm_version.hex()}\n"
            f"  Programmer ver       = 0x{self.programmer_version.hex()}\n"
            f"  S/N                  = 0x{self.serial_number.hex()}\n"
            f"  P/N (long)           = {self.part_number}\n"
            f"  Prov template ver    = v{self.prov_template_version[0]}.{self.prov_template_version[1]}\n"
            f"  Prov template tag    = 0x{self.prov_template_tag.hex()}\n"
            f"  Prov spec ver        = v{self.prov_spec_version[0]}.{self.prov_spec_version[1]}\n"
            f"  Prov spec tag        = 0x{self.prov_spec_tag.hex()}\n"
            f"  Batch ID             = 0x{self.batch_id.hex()}"
        )


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
    pair_version: int | None = None  # Paired version (boot v2 only)

    def __str__(self) -> str:
        """
        Pretty-print firmware header info.

        Maps to: lt_print_fw_header()
        """
        # Decode firmware type
        fw_types = {
            1: "RISC-V CPU FW",
            2: "SPECT FW",
        }
        type_str = fw_types.get(self.fw_type, f"Unknown ({self.fw_type})")

        # Parse version bytes (packed as major.minor.patch.build)
        ver_build = (self.version >> 0) & 0xFF
        ver_patch = (self.version >> 8) & 0xFF
        ver_minor = (self.version >> 16) & 0xFF
        ver_major = (self.version >> 24) & 0xFF
        ver_str = f"v{ver_major}.{ver_minor}.{ver_patch}"
        if ver_build:
            ver_str += f".{ver_build}"

        lines = [
            f"FirmwareHeader:",
            f"  FW type              = {self.fw_type} ({type_str})",
            f"  FW header version    = 0x{self.header_version:02X}",
            f"  FW version           = 0x{self.version:08X} ({ver_str})",
            f"  FW size              = {self.size} bytes",
            f"  GIT hash             = 0x{self.git_hash.hex()}",
            f"  Content hash         = 0x{self.content_hash.hex()}",
        ]

        if self.pair_version is not None:
            pair_build = (self.pair_version >> 0) & 0xFF
            pair_patch = (self.pair_version >> 8) & 0xFF
            pair_minor = (self.pair_version >> 16) & 0xFF
            pair_major = (self.pair_version >> 24) & 0xFF
            pair_str = f"v{pair_major}.{pair_minor}.{pair_patch}"
            if pair_build:
                pair_str += f".{pair_build}"
            lines.append(f"  Pair version         = 0x{self.pair_version:08X} ({pair_str})")

        return "\n".join(lines)


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
    def certificates(self) -> list[bytes]:
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

    @classmethod
    def from_address_dict(cls, config_dict: dict[ConfigAddress, int]) -> DeviceConfig:
        """
        Create DeviceConfig from dict mapping ConfigAddress to values.

        Args:
            config_dict: Dictionary mapping ConfigAddress enum to 32-bit values

        Returns:
            DeviceConfig instance with values from the dict
        """
        from .enums import ConfigAddress

        return cls(
            start_up=config_dict.get(ConfigAddress.START_UP, 0xFFFFFFFF),
            sensors=config_dict.get(ConfigAddress.SENSORS, 0xFFFFFFFF),
            debug=config_dict.get(ConfigAddress.DEBUG, 0xFFFFFFFF),
            gpo=config_dict.get(ConfigAddress.GPO, 0xFFFFFFFF),
            sleep_mode=config_dict.get(ConfigAddress.SLEEP_MODE, 0xFFFFFFFF),
            uap_pairing_key_write=config_dict.get(ConfigAddress.UAP_PAIRING_KEY_WRITE, 0xFFFFFFFF),
            uap_pairing_key_read=config_dict.get(ConfigAddress.UAP_PAIRING_KEY_READ, 0xFFFFFFFF),
            uap_pairing_key_invalidate=config_dict.get(ConfigAddress.UAP_PAIRING_KEY_INVALIDATE, 0xFFFFFFFF),
            uap_r_config_write_erase=config_dict.get(ConfigAddress.UAP_R_CONFIG_WRITE_ERASE, 0xFFFFFFFF),
            uap_r_config_read=config_dict.get(ConfigAddress.UAP_R_CONFIG_READ, 0xFFFFFFFF),
            uap_i_config_write=config_dict.get(ConfigAddress.UAP_I_CONFIG_WRITE, 0xFFFFFFFF),
            uap_i_config_read=config_dict.get(ConfigAddress.UAP_I_CONFIG_READ, 0xFFFFFFFF),
            uap_ping=config_dict.get(ConfigAddress.UAP_PING, 0xFFFFFFFF),
            uap_r_mem_data_write=config_dict.get(ConfigAddress.UAP_R_MEM_DATA_WRITE, 0xFFFFFFFF),
            uap_r_mem_data_read=config_dict.get(ConfigAddress.UAP_R_MEM_DATA_READ, 0xFFFFFFFF),
            uap_r_mem_data_erase=config_dict.get(ConfigAddress.UAP_R_MEM_DATA_ERASE, 0xFFFFFFFF),
            uap_random_value_get=config_dict.get(ConfigAddress.UAP_RANDOM_VALUE_GET, 0xFFFFFFFF),
            uap_ecc_key_generate=config_dict.get(ConfigAddress.UAP_ECC_KEY_GENERATE, 0xFFFFFFFF),
            uap_ecc_key_store=config_dict.get(ConfigAddress.UAP_ECC_KEY_STORE, 0xFFFFFFFF),
            uap_ecc_key_read=config_dict.get(ConfigAddress.UAP_ECC_KEY_READ, 0xFFFFFFFF),
            uap_ecc_key_erase=config_dict.get(ConfigAddress.UAP_ECC_KEY_ERASE, 0xFFFFFFFF),
            uap_ecdsa_sign=config_dict.get(ConfigAddress.UAP_ECDSA_SIGN, 0xFFFFFFFF),
            uap_eddsa_sign=config_dict.get(ConfigAddress.UAP_EDDSA_SIGN, 0xFFFFFFFF),
            uap_mcounter_init=config_dict.get(ConfigAddress.UAP_MCOUNTER_INIT, 0xFFFFFFFF),
            uap_mcounter_get=config_dict.get(ConfigAddress.UAP_MCOUNTER_GET, 0xFFFFFFFF),
            uap_mcounter_update=config_dict.get(ConfigAddress.UAP_MCOUNTER_UPDATE, 0xFFFFFFFF),
            uap_mac_and_destroy=config_dict.get(ConfigAddress.UAP_MAC_AND_DESTROY, 0xFFFFFFFF),
        )


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
