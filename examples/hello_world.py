#!/usr/bin/env python3
"""
TROPIC01 Hello World Example

This example demonstrates the basic workflow for communicating with
a TROPIC01 secure element:

1. Open connection to the device
2. Establish a secure session (with chip certificate verification)
3. Send a ping command and receive the echoed response
4. Abort the session
5. Close the connection

Usage:
    python examples/hello_world.py --port /dev/ttyACM0

Maps to: lt_ex_hello_world.c from libtropic C library
"""

import argparse
import logging
import sys

from libtropic import Tropic01
from libtropic.keys import SH0_PRIV_PROD, SH0_PUB_PROD
from libtropic.enums import PairingKeySlot

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


PING_MESSAGE = b"This is Hello World message from TROPIC01!!"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TROPIC01 Hello World Example",
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

    log.info("=" * 40)
    log.info("==== TROPIC01 Hello World Example ====")
    log.info("=" * 40)

    try:
        # Use context manager for automatic open/close
        with Tropic01(args.port) as device:
            log.info("Device initialized")

            # Start secure session with default pairing key slot 0
            # This also verifies the chip's certificate chain
            log.info("Starting Secure Session with key slot %d", PairingKeySlot.SLOT_0)
            device.verify_chip_and_start_session(
                private_key=SH0_PRIV_PROD,
                public_key=SH0_PUB_PROD,
                slot=PairingKeySlot.SLOT_0,
            )
            log.info("Secure session established")

            # Send ping command
            log.info("Sending Ping command with message:")
            log.info('    "%s"', PING_MESSAGE.decode())

            response = device.ping(PING_MESSAGE)

            log.info("Message received from TROPIC01:")
            log.info('    "%s"', response.decode())

            # Abort the session
            log.info("Aborting Secure Session")
            device.abort_session()

            log.info("Session aborted successfully")

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
