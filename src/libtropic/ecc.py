"""
ECC key operations for libtropic.

Provides key generation, storage, reading, and signing operations.
"""

from typing import TYPE_CHECKING

from .enums import EccCurve, EccSlot
from .types import EccKeyInfo

if TYPE_CHECKING:
    from .device import Tropic01


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
        from ._protocol.constants import L3_CMD_ECC_KEY_GENERATE
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        if curve not in (EccCurve.P256, EccCurve.ED25519):
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Invalid curve: {curve}"
            )

        # Build command: slot(2B LE) + curve(1B)
        cmd_data = bytes([slot_idx & 0xFF, (slot_idx >> 8) & 0xFF, int(curve)])

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_ECC_KEY_GENERATE, cmd_data)

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
        from ._protocol.constants import L3_CMD_ECC_KEY_STORE
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        if curve not in (EccCurve.P256, EccCurve.ED25519):
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Invalid curve: {curve}"
            )

        if len(private_key) != 32:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Private key must be 32 bytes, got {len(private_key)}"
            )

        # Build command: slot(2B LE) + curve(1B) + padding(12B) + key(32B)
        cmd_data = bytearray(47)  # 2 + 1 + 12 + 32
        cmd_data[0] = slot_idx & 0xFF
        cmd_data[1] = (slot_idx >> 8) & 0xFF
        cmd_data[2] = int(curve)
        # Bytes 3-14 are padding (zeros)
        cmd_data[15:47] = private_key

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_ECC_KEY_STORE, bytes(cmd_data))

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
        from ._protocol.constants import L3_CMD_ECC_KEY_READ
        from .enums import ReturnCode, EccKeyOrigin
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        # Build command: slot(2B LE)
        cmd_data = bytes([slot_idx & 0xFF, (slot_idx >> 8) & 0xFF])

        # Send command and get response
        # Response: curve(1B) + origin(1B) + padding(13B) + pubkey(32 or 64B)
        response = self._device._send_l3_command(L3_CMD_ECC_KEY_READ, cmd_data)

        # Parse response
        curve_byte = response[0]
        origin_byte = response[1]
        # Skip padding (13 bytes)
        pubkey_offset = 15  # 1 + 1 + 13

        # Determine curve and public key size
        if curve_byte == 0x01:  # P256
            curve = EccCurve.P256
            pubkey_size = 64
        elif curve_byte == 0x02:  # Ed25519
            curve = EccCurve.ED25519
            pubkey_size = 32
        else:
            raise ValueError(f"Unknown curve type: 0x{curve_byte:02X}")

        # Determine origin
        if origin_byte == 0x01:
            origin = EccKeyOrigin.GENERATED
        elif origin_byte == 0x02:
            origin = EccKeyOrigin.STORED
        else:
            raise ValueError(f"Unknown key origin: 0x{origin_byte:02X}")

        public_key = response[pubkey_offset:pubkey_offset + pubkey_size]

        return EccKeyInfo(
            curve=curve,
            origin=origin,
            public_key=public_key
        )

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
        from ._protocol.constants import L3_CMD_ECC_KEY_ERASE
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        # Build command: slot(2B LE)
        cmd_data = bytes([slot_idx & 0xFF, (slot_idx >> 8) & 0xFF])

        # Send command - response is empty (just result code)
        self._device._send_l3_command(L3_CMD_ECC_KEY_ERASE, cmd_data)

    def sign_ecdsa(
        self,
        slot: int | EccSlot,
        message: bytes
    ) -> bytes:
        """
        Sign message using ECDSA with P256 key.

        Computes ECDSA signature over the message using the private key
        in the specified slot. The key must be a P256 key.

        Note: The message is passed as a 32-byte hash. If you have a raw
        message, hash it with SHA-256 first.

        Args:
            slot: Key slot index (0-31) containing P256 key
            message: 32-byte message hash to sign

        Returns:
            64-byte signature (R || S, 32 bytes each)

        Raises:
            NoSessionError: If no secure session is active
            SlotEmptyError: If slot is empty
            InvalidKeyError: If key is invalid or wrong curve type
            ParamError: If slot is invalid or message hash length is wrong
            UnauthorizedError: If operation not permitted by UAP config

        Maps to: lt_ecc_ecdsa_sign()
        """
        from ._protocol.constants import L3_CMD_ECDSA_SIGN
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        if len(message) != 32:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Message hash must be 32 bytes, got {len(message)}"
            )

        # Build command: slot(2B LE) + padding(13B) + msg_hash(32B)
        cmd_data = bytearray(47)  # 2 + 13 + 32
        cmd_data[0] = slot_idx & 0xFF
        cmd_data[1] = (slot_idx >> 8) & 0xFF
        # Bytes 2-14 are padding (zeros)
        cmd_data[15:47] = message

        # Send command and get response
        # Response: padding(15B) + r(32B) + s(32B)
        response = self._device._send_l3_command(L3_CMD_ECDSA_SIGN, bytes(cmd_data))

        # Extract R and S (skip 15 bytes padding)
        r = response[15:47]
        s = response[47:79]

        return r + s

    # Maximum message length for EdDSA signing
    EDDSA_MSG_MAX = 4096

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
        from ._protocol.constants import L3_CMD_EDDSA_SIGN
        from .enums import ReturnCode
        from .exceptions import ParamError

        slot_idx = int(slot)
        if slot_idx < self.SLOT_MIN or slot_idx > self.SLOT_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Slot must be {self.SLOT_MIN}-{self.SLOT_MAX}, got {slot_idx}"
            )

        if len(message) > self.EDDSA_MSG_MAX:
            raise ParamError(
                ReturnCode.PARAM_ERR,
                f"Message must be at most {self.EDDSA_MSG_MAX} bytes, got {len(message)}"
            )

        # Build command: slot(2B LE) + padding(13B) + message(variable)
        cmd_data = bytearray(15 + len(message))  # 2 + 13 + len(message)
        cmd_data[0] = slot_idx & 0xFF
        cmd_data[1] = (slot_idx >> 8) & 0xFF
        # Bytes 2-14 are padding (zeros)
        cmd_data[15:] = message

        # Send command and get response
        # Response: padding(15B) + r(32B) + s(32B)
        response = self._device._send_l3_command(L3_CMD_EDDSA_SIGN, bytes(cmd_data))

        # Extract R and S (skip 15 bytes padding)
        r = response[15:47]
        s = response[47:79]

        return r + s
