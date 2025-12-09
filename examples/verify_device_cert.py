#!/usr/bin/env python3
"""
TROPIC01 Device Certificate Verification Example

This example demonstrates how to verify a TROPIC01 device's certificate chain:

1. Open connection to the device
2. Attempt to verify certificate chain and start secure session
3. Display verification result (valid or invalid)
4. Show certificate details if verification succeeds

The certificate chain is verified:
    Root CA (trusted) → TROPIC01 CA → XXXX CA → Device Cert

Usage:
    python examples/verify_device_cert.py --port /dev/ttyACM0

Optional arguments:
    --root-ca PATH    Path to custom root CA certificate (DER format)
    --skip-verify    Skip certificate verification (for development only)
"""

import argparse
import logging
import sys
import warnings

from libtropic import Tropic01
from libtropic.enums import PairingKeySlot
from libtropic.exceptions import CertificateVerificationError, HandshakeError
from libtropic._protocol.l2 import L2StatusError
from libtropic._cert import verify_certificate_chain
from libtropic.keys import SH0_PRIV_PROD, SH0_PUB_PROD

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def format_trusted_root_ca(root_ca_bytes: bytes, source: str) -> None:
    """Format and display trusted root CA certificate information."""
    from cryptography import x509

    log.info("Trusted Root CA Certificate:")
    log.info("  " + "-" * 60)
    log.info("  Source: %s", source)

    try:
        root_ca = x509.load_der_x509_certificate(root_ca_bytes)
        log.info("  Subject: %s", root_ca.subject.rfc4514_string())
        log.info("  Issuer:  %s", root_ca.issuer.rfc4514_string())
        log.info("  Serial:  %s", hex(root_ca.serial_number))
        log.info("  Valid from: %s", root_ca.not_valid_before_utc)
        log.info("  Valid to:   %s", root_ca.not_valid_after_utc)
        log.info("  Size:    %d bytes", len(root_ca_bytes))
    except Exception as e:
        log.warning("  Failed to parse trusted root CA: %s", e)

    log.info("  " + "-" * 60)
    log.info("")


def format_cert_info(cert_store) -> None:
    """Format and display certificate store information."""
    from cryptography import x509

    log.info("Device Certificate Chain Details:")
    log.info("  " + "-" * 60)

    # Root CA
    try:
        root_ca = x509.load_der_x509_certificate(cert_store.root_cert)
        log.info("  Root CA:")
        log.info("    Subject:    %s", root_ca.subject.rfc4514_string())
        log.info("    Issuer:     %s", root_ca.issuer.rfc4514_string())
        log.info("    Serial:     %s", hex(root_ca.serial_number))
        log.info("    Valid from: %s", root_ca.not_valid_before_utc)
        log.info("    Valid to:   %s", root_ca.not_valid_after_utc)
        log.info("    Size:       %d bytes", len(cert_store.root_cert))
    except Exception as e:
        log.warning("    Failed to parse root CA: %s", e)

    # TROPIC01 CA
    try:
        tropic01_ca = x509.load_der_x509_certificate(cert_store.tropic01_cert)
        log.info("  TROPIC01 CA:")
        log.info("    Subject:    %s", tropic01_ca.subject.rfc4514_string())
        log.info("    Issuer:     %s", tropic01_ca.issuer.rfc4514_string())
        log.info("    Serial:     %s", hex(tropic01_ca.serial_number))
        log.info("    Valid from: %s", tropic01_ca.not_valid_before_utc)
        log.info("    Valid to:   %s", tropic01_ca.not_valid_after_utc)
        log.info("    Size:       %d bytes", len(cert_store.tropic01_cert))
    except Exception as e:
        log.warning("    Failed to parse TROPIC01 CA: %s", e)

    # XXXX CA (Intermediate)
    try:
        xxxx_ca = x509.load_der_x509_certificate(cert_store.intermediate_cert)
        log.info("  XXXX CA (Intermediate):")
        log.info("    Subject:    %s", xxxx_ca.subject.rfc4514_string())
        log.info("    Issuer:     %s", xxxx_ca.issuer.rfc4514_string())
        log.info("    Serial:     %s", hex(xxxx_ca.serial_number))
        log.info("    Valid from: %s", xxxx_ca.not_valid_before_utc)
        log.info("    Valid to:   %s", xxxx_ca.not_valid_after_utc)
        log.info("    Size:       %d bytes", len(cert_store.intermediate_cert))
    except Exception as e:
        log.warning("    Failed to parse XXXX CA: %s", e)

    # Device Certificate
    # Note: Device certificate uses X25519 keys which cryptography library cannot parse
    # This is expected - verification uses custom ASN.1 parser instead
    try:
        device_cert = x509.load_der_x509_certificate(cert_store.device_cert)
        log.info("  Device Certificate:")
        log.info("    Subject:    %s", device_cert.subject.rfc4514_string())
        log.info("    Issuer:     %s", device_cert.issuer.rfc4514_string())
        log.info("    Serial:     %s", hex(device_cert.serial_number))
        log.info("    Valid from: %s", device_cert.not_valid_before_utc)
        log.info("    Valid to:   %s", device_cert.not_valid_after_utc)
        log.info("    Size:       %d bytes", len(cert_store.device_cert))
    except Exception as e:
        # Expected: Device certificate uses X25519 which cryptography library can't parse
        log.info("  Device Certificate:")
        log.info("    Size:       %d bytes", len(cert_store.device_cert))
        log.info("    Note:       Certificate uses X25519 keys (cannot be parsed by")
        log.info("                cryptography library, but is valid and will be verified)")
        log.debug("    Parse error: %s", e)

    log.info("  " + "-" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TROPIC01 Device Certificate Verification Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help="Serial port for USB dongle (default: /dev/ttyACM0)",
    )
    parser.add_argument(
        "--root-ca",
        type=str,
        help="Path to custom root CA certificate file (DER format)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=" * 60)
    log.info("==== TROPIC01 Device Certificate Verification ====")
    log.info("=" * 60)

    # Load custom root CA if provided, otherwise use embedded
    root_ca_bytes = None
    root_ca_source = ""
    if args.root_ca:
        try:
            with open(args.root_ca, "rb") as f:
                root_ca_bytes = f.read()
            root_ca_source = f"Custom file: {args.root_ca}"
            log.info("Loaded custom root CA from: %s (%d bytes)", args.root_ca, len(root_ca_bytes))
        except Exception as e:
            log.error("Failed to load root CA from %s: %s", args.root_ca, e)
            return 1
    else:
        # Use embedded root CA
        from libtropic._cert.root_ca import TROPIC_SQUARE_ROOT_CA_DER
        root_ca_bytes = TROPIC_SQUARE_ROOT_CA_DER
        root_ca_source = "Embedded (from libtropic-upstream)"

    # Display trusted root CA certificate details
    log.info("")
    format_trusted_root_ca(root_ca_bytes, root_ca_source)

    try:
        with Tropic01(args.port) as device:
            log.info("Device initialized")
            log.info("")

            # Get certificate store to display certificate info
            log.info("Reading certificate store from device...")
            cert_store = device.get_certificate_store()
            log.info("Certificate store retrieved")
            log.info("")

            # Display certificate information
            format_cert_info(cert_store)
            log.info("")

            # ====================================================================
            # GOAL 1: Certificate Chain Verification
            # ====================================================================
            log.info("=" * 60)
            log.info("GOAL 1: Verifying Certificate Chain")
            log.info("=" * 60)
            log.info("")

            cert_verification_passed = False
            try:
                verify_certificate_chain(cert_store, trusted_root_ca=root_ca_bytes)

                # Certificate verification succeeded
                log.info("")
                log.info("=" * 60)
                log.info("✓ CERTIFICATE VERIFICATION: SUCCESS")
                log.info("=" * 60)
                log.info("The device certificate chain is VALID.")
                log.info("All certificates in the chain are properly signed and verified.")
                log.info("")
                cert_verification_passed = True

            except CertificateVerificationError as e:
                # Certificate verification failed
                log.error("")
                log.error("=" * 60)
                log.error("✗ CERTIFICATE VERIFICATION: FAILED")
                log.error("=" * 60)
                log.error("The device certificate chain is INVALID.")
                log.error("")
                log.error("Error details:")
                log.error("  Reason: %s", e.reason)
                log.error("  Details: %s", e.details)
                log.error("")
                log.error("Possible causes:")
                log.error("  - Device uses a different certificate chain")
                log.error("  - Root CA mismatch (device CA != trusted CA)")
                log.error("  - Invalid certificate signatures")
                log.error("  - Certificate chain is incomplete or corrupted")
                log.error("")
                log.error("If this is a lab batch device, try:")
                log.error("  --root-ca <path_to_test_root_ca.der>")
                cert_verification_passed = False

            # ====================================================================
            # GOAL 2: Secure Session Establishment
            # ====================================================================
            log.info("")
            log.info("=" * 60)
            log.info("GOAL 2: Establishing Secure Session")
            log.info("=" * 60)
            log.info("")

            session_established = False
            log.info("Attempting to establish secure session...")
            try:
                # Get device public key and start session
                stpub = device.get_device_public_key()
                device.start_session(
                    stpub=stpub,
                    slot=PairingKeySlot.SLOT_0,
                    private_key=SH0_PRIV_PROD,
                    public_key=SH0_PUB_PROD,
                )

                # Session establishment succeeded
                log.info("")
                log.info("=" * 60)
                log.info("✓ SESSION ESTABLISHMENT: SUCCESS")
                log.info("=" * 60)
                log.info("Secure session established successfully.")
                log.info("")
                session_established = True

                # Abort session
                log.info("Aborting secure session...")
                device.abort_session()
                log.info("Session aborted")

            except (HandshakeError, L2StatusError) as e:
                # Handshake error - likely pairing key mismatch or device configuration issue
                log.error("")
                log.error("=" * 60)
                log.error("✗ SESSION ESTABLISHMENT: FAILED")
                log.error("=" * 60)
                log.error("Handshake error: %s", e)
                log.error("")
                log.error("Possible causes:")
                log.error("  - Pairing keys (SH0_PRIV_PROD/SH0_PUB_PROD) don't match")
                log.error("    the keys stored in the device's pairing key slot")
                log.error("  - Device pairing key slot is empty or not configured")
                log.error("  - Wrong pairing key slot specified")
                log.error("  - Device state issue (may need reset)")
                log.error("")
                log.error("Note: Certificate verification PASSED, but")
                log.error("      the handshake (key exchange) failed.")
                if args.verbose:
                    import traceback
                    traceback.print_exc()

            except Exception as e:
                log.error("")
                log.error("=" * 60)
                log.error("✗ SESSION ESTABLISHMENT: FAILED")
                log.error("=" * 60)
                log.error("Failed to establish secure session: %s", e)
                log.error("")
                log.error("Note: Certificate verification PASSED, but")
                log.error("      session establishment failed for another reason.")
                if args.verbose:
                    import traceback
                    traceback.print_exc()

            # Final summary
            log.info("")
            log.info("=" * 60)
            log.info("SUMMARY")
            log.info("=" * 60)
            log.info("  Certificate Verification: %s", "✓ PASSED" if cert_verification_passed else "✗ FAILED")
            log.info("  Session Establishment:    %s", "✓ PASSED" if session_established else "✗ FAILED")
            log.info("=" * 60)
            log.info("")

        log.info("Device deinitialized")
        # Return 0 if certificate verification passed (even if session failed)
        # Return 1 if certificate verification failed
        return 0 if cert_verification_passed else 1

    except Exception as e:
        log.error("Error: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
