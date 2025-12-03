"""
CRC16 calculation for TROPIC01 L2 protocol.

Uses CRC-16/BUYPASS (also known as CRC-16/VERIFONE) with:
    - Polynomial: 0x8005
    - Initial value: 0x0000
    - Final XOR: 0x0000
    - Input reflected: No
    - Output reflected: Yes (swap bytes)
"""


_CRC16_POLYNOMIAL = 0x8005
_CRC16_INITIAL = 0x0000


def _crc16_byte(data_byte: int, crc: int) -> int:
    """Process a single byte through the CRC16 algorithm."""
    crc ^= (data_byte << 8)
    for _ in range(8):
        if crc & 0x8000:
            crc = ((crc << 1) ^ _CRC16_POLYNOMIAL) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
    return crc


def crc16(data: bytes) -> int:
    """
    Calculate CRC16 checksum for the given data.

    Args:
        data: Input data bytes

    Returns:
        16-bit CRC value (byte-swapped per TROPIC01 protocol)
    """
    crc = _CRC16_INITIAL
    for byte in data:
        crc = _crc16_byte(byte, crc)
    # Byte-swap the result
    return ((crc << 8) | (crc >> 8)) & 0xFFFF


def add_crc(frame: bytearray) -> None:
    """
    Calculate and append CRC to an L2 request frame in-place.

    The CRC is calculated over REQ_ID + REQ_LEN + REQ_DATA and appended
    as 2 bytes (big-endian) at the end.

    Args:
        frame: L2 request frame (must have space for 2-byte CRC at end)
               Format: [REQ_ID, REQ_LEN, ...DATA..., CRC_HI, CRC_LO]

    Note:
        The frame must be pre-allocated with 2 extra bytes at the end for CRC.
    """
    # REQ_LEN is at offset 1, tells us how many data bytes follow
    req_len = frame[1]
    # CRC covers: REQ_ID(1) + REQ_LEN(1) + DATA(req_len)
    crc_data_len = 1 + 1 + req_len
    checksum = crc16(bytes(frame[:crc_data_len]))
    # Append CRC (big-endian)
    frame[crc_data_len] = (checksum >> 8) & 0xFF
    frame[crc_data_len + 1] = checksum & 0xFF


def verify_crc(frame: bytes) -> bool:
    """
    Verify CRC of an L2 response frame.

    The CRC is calculated over STATUS + RSP_LEN + RSP_DATA and compared
    against the last 2 bytes.

    Args:
        frame: L2 response frame (without chip_status byte)
               Format: [STATUS, RSP_LEN, ...DATA..., CRC_HI, CRC_LO]

    Returns:
        True if CRC matches, False otherwise
    """
    if len(frame) < 4:  # Minimum: STATUS + LEN + CRC(2)
        return False

    # RSP_LEN is at offset 1 (after STATUS)
    rsp_len = frame[1]
    # CRC covers: STATUS(1) + RSP_LEN(1) + DATA(rsp_len)
    crc_data_len = 1 + 1 + rsp_len

    if len(frame) < crc_data_len + 2:
        return False

    # Extract and calculate CRCs
    expected_crc = (frame[crc_data_len] << 8) | frame[crc_data_len + 1]
    calculated_crc = crc16(frame[:crc_data_len])

    return expected_crc == calculated_crc

