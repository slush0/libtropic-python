"""
X.509 certificate chain verification for TROPIC01 devices.

Verifies the complete certificate chain from the device certificate
up to the trusted root CA. The chain structure is:

    Root CA (trusted) → TROPIC01 CA → XXXX CA → Device Cert

Based on tropic-grub/cert_verify.c implementation.
"""

from __future__ import annotations

import datetime
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..exceptions import CertificateVerificationError

if TYPE_CHECKING:
    from ..types import CertificateStore


# ASN.1 DER tag constants
ASN1_SEQUENCE = 0x30
ASN1_BIT_STRING = 0x03
ASN1_OID = 0x06


@dataclass
class CertComponents:
    """Parsed certificate components for signature verification."""

    tbs: bytes  # To-Be-Signed data
    signature: bytes  # Signature value
    hash_algorithm: hashes.HashAlgorithm  # Hash algorithm used


def _parse_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    """
    Parse ASN.1 DER length encoding.

    Args:
        data: Certificate bytes
        offset: Current position in data

    Returns:
        Tuple of (length_value, new_offset)
    """
    if offset >= len(data):
        raise CertificateVerificationError("Invalid ASN.1", "Unexpected end of data")

    first_byte = data[offset]

    if first_byte < 0x80:
        # Short form: length in single byte
        return first_byte, offset + 1
    elif first_byte == 0x80:
        # Indefinite length - not supported
        raise CertificateVerificationError("Invalid ASN.1", "Indefinite length not supported")
    else:
        # Long form: first byte indicates number of length bytes
        num_bytes = first_byte & 0x7F
        if num_bytes > 2:
            raise CertificateVerificationError("Invalid ASN.1", "Length > 2 bytes not supported")

        if offset + 1 + num_bytes > len(data):
            raise CertificateVerificationError("Invalid ASN.1", "Truncated length")

        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data[offset + 1 + i]

        return length, offset + 1 + num_bytes


def _extract_tbs_and_signature(cert_der: bytes) -> CertComponents:
    """
    Extract TBS (To-Be-Signed) and signature from a DER-encoded X.509 certificate.

    This is needed because the device certificate uses X25519 key which
    the cryptography library cannot parse. We manually extract components
    for signature verification.

    X.509 Certificate structure:
        Certificate ::= SEQUENCE {
            tbsCertificate       TBSCertificate,
            signatureAlgorithm   AlgorithmIdentifier,
            signatureValue       BIT STRING
        }

    Args:
        cert_der: DER-encoded certificate

    Returns:
        CertComponents with TBS data, signature, and hash algorithm
    """
    pos = 0

    # Parse outer SEQUENCE (Certificate)
    if cert_der[pos] != ASN1_SEQUENCE:
        raise CertificateVerificationError("Invalid certificate", "Expected SEQUENCE")
    pos += 1

    outer_len, pos = _parse_asn1_length(cert_der, pos)
    _ = outer_len  # Used for validation only

    # Parse TBSCertificate SEQUENCE header
    if cert_der[pos] != ASN1_SEQUENCE:
        raise CertificateVerificationError("Invalid certificate", "Expected TBS SEQUENCE")
    tbs_tag_pos = pos
    pos += 1

    tbs_content_len, pos = _parse_asn1_length(cert_der, pos)

    # TBS includes tag + length + content
    tbs_end = pos + tbs_content_len
    tbs_data = cert_der[tbs_tag_pos:tbs_end]

    # Skip TBS content
    pos = tbs_end

    # Parse signatureAlgorithm SEQUENCE
    if cert_der[pos] != ASN1_SEQUENCE:
        raise CertificateVerificationError("Invalid certificate", "Expected sigAlg SEQUENCE")
    pos += 1

    sig_alg_len, pos = _parse_asn1_length(cert_der, pos)
    sig_alg_end = pos + sig_alg_len

    # Parse the algorithm OID
    if cert_der[pos] != ASN1_OID:
        raise CertificateVerificationError("Invalid certificate", "Expected sigAlg OID")
    pos += 1

    oid_len, pos = _parse_asn1_length(cert_der, pos)
    oid_bytes = cert_der[pos : pos + oid_len]

    # Determine hash algorithm from OID
    # ECDSA-SHA512 OID: 1.2.840.10045.4.3.4 = 2A 86 48 CE 3D 04 03 04
    # ECDSA-SHA384 OID: 1.2.840.10045.4.3.3 = 2A 86 48 CE 3D 04 03 03
    # ECDSA-SHA256 OID: 1.2.840.10045.4.3.2 = 2A 86 48 CE 3D 04 03 02
    ecdsa_sha512_oid = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04])
    ecdsa_sha384_oid = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03])
    ecdsa_sha256_oid = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])

    if oid_bytes == ecdsa_sha512_oid:
        hash_alg: hashes.HashAlgorithm = hashes.SHA512()
    elif oid_bytes == ecdsa_sha384_oid:
        hash_alg = hashes.SHA384()
    elif oid_bytes == ecdsa_sha256_oid:
        hash_alg = hashes.SHA256()
    else:
        raise CertificateVerificationError(
            "Unsupported signature algorithm", f"OID: {oid_bytes.hex()}"
        )

    # Skip to end of signatureAlgorithm
    pos = sig_alg_end

    # Parse signatureValue BIT STRING
    if cert_der[pos] != ASN1_BIT_STRING:
        raise CertificateVerificationError("Invalid certificate", "Expected BIT STRING")
    pos += 1

    sig_len, pos = _parse_asn1_length(cert_der, pos)

    # BIT STRING has leading byte for unused bits (should be 0)
    if sig_len < 1:
        raise CertificateVerificationError("Invalid certificate", "Empty signature")

    unused_bits = cert_der[pos]
    if unused_bits != 0:
        raise CertificateVerificationError("Invalid certificate", "Non-zero unused bits")

    # Signature data follows
    signature = cert_der[pos + 1 : pos + sig_len]

    return CertComponents(tbs=tbs_data, signature=signature, hash_algorithm=hash_alg)


def _verify_device_cert_signature(
    device_cert_der: bytes, issuer_public_key: ec.EllipticCurvePublicKey
) -> None:
    """
    Verify device certificate signature using the issuer's (XXXX CA) public key.

    The device certificate uses X25519 for its public key, which the cryptography
    library cannot parse as a full X.509 certificate. We manually extract the
    TBS and signature to verify.

    Args:
        device_cert_der: DER-encoded device certificate
        issuer_public_key: Public key from XXXX CA certificate

    Raises:
        CertificateVerificationError: If signature verification fails
    """
    # Extract components
    components = _extract_tbs_and_signature(device_cert_der)

    # Verify signature
    try:
        issuer_public_key.verify(
            components.signature, components.tbs, ec.ECDSA(components.hash_algorithm)
        )
    except InvalidSignature as err:
        raise CertificateVerificationError(
            "Device certificate signature invalid",
            "Certificate is not signed by XXXX CA - may indicate counterfeit device",
        ) from err


def verify_certificate_chain(
    cert_store: CertificateStore,
    trusted_root_ca: bytes | None = None,
) -> None:
    """
    Verify TROPIC01 certificate chain.

    Verifies the complete certificate chain from the device certificate
    up to the trusted root CA. The chain structure is:

        Root CA (trusted) → TROPIC01 CA → XXXX CA → Device Cert

    All certificates must:
    - Have valid signatures chaining to the trusted root
    - Be present (non-empty)
    - Device's root CA must match the trusted root CA

    Args:
        cert_store: Certificate store from device (via get_certificate_store())
        trusted_root_ca: DER-encoded trusted root CA certificate.
                        If None, uses embedded Tropic Square root CA.

    Raises:
        CertificateVerificationError: If any verification step fails
    """
    from .root_ca import TROPIC_SQUARE_ROOT_CA_DER

    # Use embedded root CA if none provided
    if trusted_root_ca is None:
        trusted_root_ca = TROPIC_SQUARE_ROOT_CA_DER

    # Validate input
    if not cert_store:
        raise CertificateVerificationError("Invalid certificate store", "Store is None")

    # Check all certificates are present
    if not cert_store.root_cert:
        raise CertificateVerificationError("Missing certificate", "Device root CA is empty")
    if not cert_store.tropic01_cert:
        raise CertificateVerificationError("Missing certificate", "TROPIC01 CA is empty")
    if not cert_store.intermediate_cert:
        raise CertificateVerificationError("Missing certificate", "XXXX CA is empty")
    if not cert_store.device_cert:
        raise CertificateVerificationError("Missing certificate", "Device certificate is empty")

    # Step 1: Compare device's root CA with trusted root CA
    # This is critical - we must trust an external source, not just what device provides
    if cert_store.root_cert != trusted_root_ca:
        raise CertificateVerificationError(
            "Root CA mismatch",
            f"Device root CA ({len(cert_store.root_cert)} bytes) does not match "
            f"trusted root CA ({len(trusted_root_ca)} bytes). "
            "This may indicate a different certificate chain or counterfeit device.",
        )

    # Step 2: Parse and verify CA chain using cryptography library
    try:
        root_ca_cert = x509.load_der_x509_certificate(trusted_root_ca)
    except Exception as e:
        raise CertificateVerificationError("Failed to parse root CA", str(e)) from e

    try:
        tropic01_ca_cert = x509.load_der_x509_certificate(cert_store.tropic01_cert)
    except Exception as e:
        raise CertificateVerificationError("Failed to parse TROPIC01 CA", str(e)) from e

    try:
        xxxx_ca_cert = x509.load_der_x509_certificate(cert_store.intermediate_cert)
    except Exception as e:
        raise CertificateVerificationError("Failed to parse XXXX CA", str(e)) from e

    # Verify TROPIC01 CA is signed by Root CA
    try:
        root_public_key = root_ca_cert.public_key()
        if not isinstance(root_public_key, ec.EllipticCurvePublicKey):
            raise CertificateVerificationError(
                "Invalid root CA", "Root CA must have EC public key"
            )
        root_public_key.verify(
            tropic01_ca_cert.signature,
            tropic01_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(tropic01_ca_cert.signature_hash_algorithm),  # type: ignore[arg-type]
        )
    except InvalidSignature as err:
        raise CertificateVerificationError(
            "TROPIC01 CA signature invalid", "Not signed by root CA"
        ) from err
    except Exception as e:
        raise CertificateVerificationError("Failed to verify TROPIC01 CA signature", str(e)) from e

    # Verify XXXX CA is signed by TROPIC01 CA
    try:
        tropic01_public_key = tropic01_ca_cert.public_key()
        if not isinstance(tropic01_public_key, ec.EllipticCurvePublicKey):
            raise CertificateVerificationError(
                "Invalid TROPIC01 CA", "TROPIC01 CA must have EC public key"
            )
        tropic01_public_key.verify(
            xxxx_ca_cert.signature,
            xxxx_ca_cert.tbs_certificate_bytes,
            ec.ECDSA(xxxx_ca_cert.signature_hash_algorithm),  # type: ignore[arg-type]
        )
    except InvalidSignature as err:
        raise CertificateVerificationError(
            "XXXX CA signature invalid", "Not signed by TROPIC01 CA"
        ) from err
    except Exception as e:
        raise CertificateVerificationError("Failed to verify XXXX CA signature", str(e)) from e

    # Step 3: Verify device certificate signature using XXXX CA's public key
    # Device cert has X25519 key which cryptography can't parse as full X509,
    # so we use custom ASN.1 parsing
    xxxx_public_key = xxxx_ca_cert.public_key()
    if not isinstance(xxxx_public_key, ec.EllipticCurvePublicKey):
        raise CertificateVerificationError(
            "Invalid XXXX CA", "XXXX CA must have EC public key"
        )
    _verify_device_cert_signature(cert_store.device_cert, xxxx_public_key)

    # Step 4: Check certificate validity times (with warning for time issues)
    now = datetime.datetime.now(datetime.timezone.utc)

    for cert, name in [
        (root_ca_cert, "Root CA"),
        (tropic01_ca_cert, "TROPIC01 CA"),
        (xxxx_ca_cert, "XXXX CA"),
    ]:
        # Check not-before
        not_valid_before = cert.not_valid_before_utc
        if now < not_valid_before:
            warnings.warn(
                f"{name} certificate not yet valid (valid from {not_valid_before}). "
                "System time may be incorrect.",
                UserWarning,
                stacklevel=2,
            )

        # Check not-after
        not_valid_after = cert.not_valid_after_utc
        if now > not_valid_after:
            warnings.warn(
                f"{name} certificate expired (expired {not_valid_after}). "
                "System time may be incorrect, or certificate needs renewal.",
                UserWarning,
                stacklevel=2,
            )

    # All verifications passed
