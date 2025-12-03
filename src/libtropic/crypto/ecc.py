"""
ECC key operations for libtropic.

Provides key generation, storage, reading, and signing operations.
"""

from typing import TYPE_CHECKING

from ..enums import EccCurve, EccSlot
from ..types import EccKeyInfo

if TYPE_CHECKING:
    from ..device import Tropic01


class EccKeys:
    """
    ECC key operations for TROPIC01.

    Manages 32 ECC key slots (0-31) supporting P256 and Ed25519 curves.
    All operations require an active secure session.

    Example:
        with Tropic01("/dev/ttyACM0") as device:
            device.start_session(priv_key, pub_key, slot=0)

            # Generate a new Ed25519 key
            device.ecc.generate(slot=0, curve=EccCurve.ED25519)

            # Read the public key
            key_info = device.ecc.read(slot=0)
            print(f"Public key: {key_info.public_key.hex()}")

            # Sign a message
            signature = device.ecc.sign_eddsa(slot=0, message=b"Hello, World!")
    """

    # Slot limits
    SLOT_MIN = 0
    SLOT_MAX = 31

    def __init__(self, device: 'Tropic01'):
        """
        Initialize ECC operations module.

        Args:
            device: Parent Tropic01 device instance
        """
        self._device = device

    def generate(
        self,
        slot: int | EccSlot,
        curve: EccCurve
    ) -> None:
        """
        Generate new ECC key pair in specified slot.

        Generates a new private/public key pair on-chip. The private key
        never leaves the secure element.

        Args:
            slot: Key slot index (0-31)
            curve: Elliptic curve type (P256 or ED25519)

        Raises:
            NoSessionError: If no secure session is active
            SlotNotEmptyError: If slot already contains a key
            ParamError: If slot or curve is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_key_generate()
        """
        raise NotImplementedError()

    def store(
        self,
        slot: int | EccSlot,
        curve: EccCurve,
        private_key: bytes
    ) -> None:
        """
        Store existing private key in specified slot.

        Imports an externally-generated private key into the secure element.

        Args:
            slot: Key slot index (0-31)
            curve: Elliptic curve type (P256 or ED25519)
            private_key: 32-byte private key to store

        Raises:
            NoSessionError: If no secure session is active
            SlotNotEmptyError: If slot already contains a key
            ParamError: If slot, curve, or key is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_key_store()
        """
        raise NotImplementedError()

    def read(self, slot: int | EccSlot) -> EccKeyInfo:
        """
        Read public key and metadata from specified slot.

        Returns the public key corresponding to the private key in the slot,
        along with curve type and key origin.

        Args:
            slot: Key slot index (0-31)

        Returns:
            EccKeyInfo containing public key, curve, and origin

        Raises:
            NoSessionError: If no secure session is active
            SlotEmptyError: If slot is empty
            InvalidKeyError: If key is corrupted
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_key_read()
        """
        raise NotImplementedError()

    def erase(self, slot: int | EccSlot) -> None:
        """
        Erase key from specified slot.

        Permanently deletes the key material from the slot.

        Args:
            slot: Key slot index (0-31)

        Raises:
            NoSessionError: If no secure session is active
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_key_erase()
        """
        raise NotImplementedError()

    def sign_ecdsa(
        self,
        slot: int | EccSlot,
        message: bytes
    ) -> bytes:
        """
        Sign message using ECDSA with P256 key.

        Computes ECDSA signature over the message using the private key
        in the specified slot. The key must be a P256 key.

        Args:
            slot: Key slot index (0-31) containing P256 key
            message: Message bytes to sign (any length, will be hashed)

        Returns:
            64-byte signature (R || S, 32 bytes each)

        Raises:
            NoSessionError: If no secure session is active
            SlotEmptyError: If slot is empty
            InvalidKeyError: If key is invalid or wrong curve type
            ParamError: If slot is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_ecdsa_sign()
        """
        raise NotImplementedError()

    def sign_eddsa(
        self,
        slot: int | EccSlot,
        message: bytes
    ) -> bytes:
        """
        Sign message using EdDSA with Ed25519 key.

        Computes Ed25519 signature over the message using the private key
        in the specified slot. The key must be an Ed25519 key.

        Args:
            slot: Key slot index (0-31) containing Ed25519 key
            message: Message bytes to sign (max 4096 bytes)

        Returns:
            64-byte signature (R || S, 32 bytes each)

        Raises:
            NoSessionError: If no secure session is active
            SlotEmptyError: If slot is empty
            InvalidKeyError: If key is invalid or wrong curve type
            ParamError: If slot or message length is invalid
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_eddsa_sign()
        """
        raise NotImplementedError()
