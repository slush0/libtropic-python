"""
Certificate verification module for TROPIC01 devices.

Provides X.509 certificate chain verification to ensure communication
with genuine Tropic Square hardware.
"""

from ..exceptions import CertificateVerificationError
from .root_ca import TROPIC_SQUARE_ROOT_CA_DER
from .verify import verify_certificate_chain

__all__ = [
    "CertificateVerificationError",
    "TROPIC_SQUARE_ROOT_CA_DER",
    "verify_certificate_chain",
]
