#!/usr/bin/env python3
"""
TROPIC01 MAC and Destroy PIN Verification Example

This example demonstrates TROPIC01's flagship feature - the "MAC and Destroy"
PIN verification engine. This provides secure PIN-based authentication with
anti-hammering protection.

How it works:
- M&D uses slots in TROPIC01's flash memory - one slot per PIN entry attempt
- Slots are initialized when a new PIN is set up
- Each wrong PIN attempt destroys one slot
- When the correct PIN is entered, slots are reinitialized (attempt limit reset)
- If all slots are destroyed, the secret is irrecoverable

This example:
1. Generates a random master secret
2. Sets up a PIN with M&D slots (stores encrypted secrets in R-Memory)
3. Demonstrates wrong PIN attempts (destroys slots)
4. Verifies correct PIN (reinitializes slots, recovers final key)

WARNING: This example modifies R-Memory slot 511 and M&D slots.
         Run only on test/development devices.

For detailed protocol documentation, see ODN_TR01_app_002_pin_verif.pdf

Usage:
    python examples/mac_and_destroy.py --port /dev/ttyACM0

Maps to: lt_ex_macandd.c from libtropic C library
"""

import argparse
import logging
import struct
import sys
from dataclasses import dataclass

from libtropic import Tropic01
from libtropic._cal.hmac_sha256 import HASH_LENGTH, hmac_sha256
from libtropic.enums import PairingKeySlot
from libtropic.keys import SH0_PRIV_PROD, SH0_PUB_PROD

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# R-Memory slot used for storing M&D NVM data (last slot in user memory)
R_MEM_DATA_SLOT_MACANDD = 511

# M&D data size (returned from mac_and_destroy operation)
MAC_AND_DESTROY_DATA_SIZE = 32

# Master secret size (high entropy input for key derivation)
MASTER_SECRET_SIZE = 32

# PIN constraints
PIN_SIZE_MIN = 4
PIN_SIZE_MAX = 8

# Additional data constraints (e.g., hardware ID)
ADD_DATA_SIZE_MAX = 128

# Number of PIN attempts allowed (M&D rounds)
MACANDD_ROUNDS = 12


# =============================================================================
# NVM Data Structure
# =============================================================================

@dataclass
class MacAndDestroyNVM:
    """
    Non-volatile memory data for MAC and Destroy PIN scheme.

    This structure is stored in R-Memory and persists across power cycles.
    """
    # Current attempt index (remaining attempts)
    i: int
    # Encrypted copies of master secret (one per round)
    ci: list[bytes]  # List of 32-byte encrypted secrets
    # Tag for verifying recovered secret
    t: bytes  # 32-byte HMAC tag

    def to_bytes(self) -> bytes:
        """Serialize NVM data for storage."""
        data = struct.pack("B", self.i)
        for c in self.ci:
            data += c
        data += self.t
        return data

    @classmethod
    def from_bytes(cls, data: bytes, rounds: int) -> "MacAndDestroyNVM":
        """Deserialize NVM data from storage."""
        i = data[0]
        offset = 1
        ci = []
        for _ in range(rounds):
            ci.append(data[offset:offset + MAC_AND_DESTROY_DATA_SIZE])
            offset += MAC_AND_DESTROY_DATA_SIZE
        t = data[offset:offset + HASH_LENGTH]
        return cls(i=i, ci=ci, t=t)


# =============================================================================
# Encryption Functions
# =============================================================================

def encrypt(data: bytes, key: bytes) -> bytes:
    """
    Simple XOR encryption (32 bytes).

    NOTE: This is a placeholder - replace with proper encryption (e.g., AES-GCM)
    in production code.
    """
    return bytes(d ^ k for d, k in zip(data, key, strict=True))


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    Simple XOR decryption (32 bytes).

    NOTE: This is a placeholder - replace with proper decryption in production.
    """
    return bytes(d ^ k for d, k in zip(data, key, strict=True))


# =============================================================================
# KDF (Key Derivation Function)
# =============================================================================

def kdf(key: bytes, data: bytes) -> bytes:
    """
    Key derivation function using HMAC-SHA256.

    Args:
        key: Secret key (32 bytes)
        data: Input data for derivation

    Returns:
        32-byte derived key
    """
    return hmac_sha256(key, data)


# =============================================================================
# PIN Setup Function
# =============================================================================

def new_pin_setup(
    device: Tropic01,
    master_secret: bytes,
    pin: bytes,
    additional_data: bytes | None = None,
) -> bytes:
    """
    Set up a new PIN with MAC and Destroy scheme.

    This function:
    1. Initializes M&D slots in TROPIC01's flash
    2. Derives encryption keys from PIN
    3. Stores encrypted copies of master_secret in NVM
    4. Returns the final_key (derived from master_secret)

    Args:
        device: Connected Tropic01 device (with active session)
        master_secret: 32 bytes of high-entropy random data
        pin: User PIN (4-8 bytes)
        additional_data: Optional additional data (e.g., hardware ID)

    Returns:
        32-byte final_key derived from master_secret

    Raises:
        ValueError: If parameters are invalid
    """
    # Validate parameters
    if len(master_secret) != MASTER_SECRET_SIZE:
        raise ValueError(f"master_secret must be {MASTER_SECRET_SIZE} bytes")
    if not (PIN_SIZE_MIN <= len(pin) <= PIN_SIZE_MAX):
        raise ValueError(f"PIN must be {PIN_SIZE_MIN}-{PIN_SIZE_MAX} bytes")

    # Build KDF input (PIN || additional_data)
    kdf_input = pin
    if additional_data:
        if len(additional_data) > ADD_DATA_SIZE_MAX:
            raise ValueError(f"additional_data exceeds {ADD_DATA_SIZE_MAX} bytes")
        kdf_input = pin + additional_data
        log.info("Using additional data in M&D sequence (%d bytes)", len(additional_data))
    else:
        log.info("No additional data will be used in the following M&D sequence")

    # Initialize NVM structure
    nvm = MacAndDestroyNVM(
        i=MACANDD_ROUNDS,
        ci=[b"\x00" * MAC_AND_DESTROY_DATA_SIZE for _ in range(MACANDD_ROUNDS)],
        t=b"\x00" * HASH_LENGTH,
    )

    # Erase R-Memory slot for NVM storage
    log.info("Erasing R_Mem User slot %d...", R_MEM_DATA_SLOT_MACANDD)
    device.memory.erase(R_MEM_DATA_SLOT_MACANDD)
    log.info("    OK")

    # Compute tag: t = KDF(master_secret, 0x00)
    # Used later to verify recovered secret
    nvm.t = kdf(master_secret, b"\x00")

    # Compute u = KDF(master_secret, 0x01)
    # This value initializes M&D slots
    u = kdf(master_secret, b"\x01")

    # Compute v = KDF(0, PIN||A)
    # Used to get w_i from M&D operation
    zeros = b"\x00" * 32
    v = kdf(zeros, kdf_input)

    # Initialize M&D slots and derive encryption keys
    for slot_idx in range(MACANDD_ROUNDS):
        # Initialize slot with u
        log.info("Doing M&D sequence to initialize slot %d...", slot_idx)
        device.mac_and_destroy.execute(slot_idx, u)
        log.info("    OK")

        # Overwrite slot with v to get w_i
        log.info("Doing M&D sequence to get w_%d...", slot_idx)
        w_i = device.mac_and_destroy.execute(slot_idx, v)
        log.info("    OK")

        # Reinitialize slot with u for future use
        log.info("Doing M&D sequence to reinitialize slot %d...", slot_idx)
        device.mac_and_destroy.execute(slot_idx, u)
        log.info("    OK")

        # Derive encryption key: k_i = KDF(w_i, PIN||A)
        k_i = kdf(w_i, kdf_input)

        # Encrypt master_secret with k_i and store in NVM
        nvm.ci[slot_idx] = encrypt(master_secret, k_i)

    # Store NVM data in R-Memory
    log.info("Writing NVM data into R_Mem User slot %d...", R_MEM_DATA_SLOT_MACANDD)
    device.memory.write(R_MEM_DATA_SLOT_MACANDD, nvm.to_bytes())
    log.info("    OK")

    # Derive and return final_key = KDF(master_secret, "2")
    final_key = kdf(master_secret, b"2")

    return final_key


# =============================================================================
# PIN Entry Check Function
# =============================================================================

def pin_entry_check(
    device: Tropic01,
    pin: bytes,
    additional_data: bytes | None = None,
) -> bytes:
    """
    Verify PIN and recover final_key.

    This function:
    1. Decrements attempt counter (writes to NVM immediately)
    2. Executes M&D to get w_i
    3. Derives decryption key and decrypts master_secret
    4. Verifies tag - if match, PIN is correct
    5. Reinitializes remaining slots on success

    Args:
        device: Connected Tropic01 device (with active session)
        pin: User PIN to verify (4-8 bytes)
        additional_data: Optional additional data (must match setup)

    Returns:
        32-byte final_key if PIN is correct

    Raises:
        ValueError: If PIN is incorrect or no attempts remaining
    """
    # Validate PIN length
    if not (PIN_SIZE_MIN <= len(pin) <= PIN_SIZE_MAX):
        raise ValueError(f"PIN must be {PIN_SIZE_MIN}-{PIN_SIZE_MAX} bytes")

    # Build KDF input
    kdf_input = pin
    if additional_data:
        if len(additional_data) > ADD_DATA_SIZE_MAX:
            raise ValueError(f"additional_data exceeds {ADD_DATA_SIZE_MAX} bytes")
        kdf_input = pin + additional_data
        log.info("Using additional data in M&D sequence (%d bytes)", len(additional_data))
    else:
        log.info("No additional data will be used in the following M&D sequence")

    # Load NVM data from R-Memory
    log.info("Reading M&D data from R_Mem User slot %d...", R_MEM_DATA_SLOT_MACANDD)
    nvm_data = device.memory.read(R_MEM_DATA_SLOT_MACANDD)
    nvm = MacAndDestroyNVM.from_bytes(nvm_data, MACANDD_ROUNDS)
    log.info("    OK")

    # Check remaining attempts
    log.info("Checking if nvm.i != 0...")
    if nvm.i == 0:
        log.error("No attempts remaining!")
        raise ValueError("No PIN attempts remaining - secret is irrecoverable")
    log.info("    OK (remaining attempts: %d)", nvm.i)

    # Decrement attempt counter BEFORE verification (anti-hammering)
    nvm.i -= 1
    current_slot = nvm.i  # Use the slot that was just "consumed"

    # Persist decremented counter immediately
    log.info(
        "Writing back M&D data into R_Mem User slot %d (decrement counter)...",
        R_MEM_DATA_SLOT_MACANDD,
    )
    device.memory.erase(R_MEM_DATA_SLOT_MACANDD)
    device.memory.write(R_MEM_DATA_SLOT_MACANDD, nvm.to_bytes())
    log.info("    OK")

    # Compute v' = KDF(0, PIN'||A)
    zeros = b"\x00" * 32
    v_prime = kdf(zeros, kdf_input)

    # Execute M&D to get w'_i
    log.info("Doing M&D sequence on slot %d...", current_slot)
    w_prime = device.mac_and_destroy.execute(current_slot, v_prime)
    log.info("    OK")

    # Derive decryption key: k'_i = KDF(w', PIN'||A)
    k_prime = kdf(w_prime, kdf_input)

    # Decrypt master_secret candidate
    s_prime = decrypt(nvm.ci[current_slot], k_prime)

    # Verify tag: t' = KDF(s', 0x00)
    t_prime = kdf(s_prime, b"\x00")

    if t_prime != nvm.t:
        log.warning("PIN verification FAILED - tags don't match")
        raise ValueError("Incorrect PIN")

    log.info("PIN verification SUCCESSFUL")

    # Reinitialize remaining slots (reset attempt counter)
    u = kdf(s_prime, b"\x01")

    for slot_idx in range(current_slot, MACANDD_ROUNDS - 1):
        log.info("Doing M&D sequence to reinitialize slot %d...", slot_idx)
        device.mac_and_destroy.execute(slot_idx, u)
        log.info("    OK")

    # Reset attempt counter
    nvm.i = MACANDD_ROUNDS

    # Persist reset counter
    log.info("Writing M&D data into R_Mem User slot %d (reset counter)...", R_MEM_DATA_SLOT_MACANDD)
    device.memory.erase(R_MEM_DATA_SLOT_MACANDD)
    device.memory.write(R_MEM_DATA_SLOT_MACANDD, nvm.to_bytes())
    log.info("    OK")

    # Derive and return final_key
    final_key = kdf(s_prime, b"2")

    return final_key


# =============================================================================
# Main Example
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="TROPIC01 MAC and Destroy PIN Verification Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port for USB dongle (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=" * 46)
    log.info("==== TROPIC01 Mac and Destroy Example ====")
    log.info("=" * 46)

    # Example PIN (additional_data can be used for hardware ID binding)
    correct_pin = bytes([1, 2, 3, 4])
    wrong_pin = bytes([2, 2, 3, 4])

    try:
        with Tropic01(args.port) as device:
            log.info("Device initialized")

            # Start secure session
            log.info("Starting Secure Session with key slot %d", PairingKeySlot.SLOT_0)
            device.verify_chip_and_start_session(
                private_key=SH0_PRIV_PROD,
                public_key=SH0_PUB_PROD,
                slot=PairingKeySlot.SLOT_0,
            )
            log.info("Secure session established")
            log.info("")

            # Generate random master secret
            log.info("Initializing Mac And Destroy")
            log.info("Generating random master_secret...")
            master_secret = device.random.get_bytes(MASTER_SECRET_SIZE)
            log.info("    OK")
            log.info("Generated master_secret: %s", master_secret.hex())
            log.info("")

            # Set up PIN
            log.info("Setting the user PIN...")
            final_key_initialized = new_pin_setup(
                device,
                master_secret,
                correct_pin,
                additional_data=None,  # Not using additional data in this example
            )
            log.info("    OK")
            log.info("Initialized final_key: %s", final_key_initialized.hex())
            log.info("")

            # Test wrong PIN attempts (destroy slots)
            log.info("Doing %d PIN check attempts with wrong PIN...", MACANDD_ROUNDS - 1)
            for attempt in range(1, MACANDD_ROUNDS):
                log.info("    Inputting wrong PIN -> slot #%d destroyed", attempt)
                try:
                    pin_entry_check(device, wrong_pin, additional_data=None)
                    log.error("ERROR: Wrong PIN should have failed!")
                    return 1
                except ValueError:
                    # Expected - wrong PIN
                    pass
                log.info("        Secret (invalid): %s", "00" * 32)
            log.info("    OK")
            log.info("")

            # Verify correct PIN (recovers key and resets slots)
            log.info("Doing final PIN attempt with correct PIN...")
            final_key_exported = pin_entry_check(device, correct_pin, additional_data=None)
            log.info("    Exported final_key: %s", final_key_exported.hex())
            log.info("    OK")
            log.info("")

            # Verify keys match
            if final_key_initialized == final_key_exported:
                log.info("SUCCESS: final_key and final_key_exported MATCH")
            else:
                log.error("ERROR: final_key and final_key_exported DO NOT MATCH")
                return 1

            # Abort session
            log.info("")
            log.info("Aborting Secure Session")
            device.abort_session()

        log.info("Device deinitialized")
        return 0

    except Exception as e:
        log.error("Error: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
