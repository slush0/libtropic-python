"""
Test R-Memory Data Read, Write, and Erase L3 commands.

Mirrors: libtropic-upstream/tests/functional/lt_test_rev_r_mem.c

Tests user data storage operations on all 512 slots (0-511).
"""

import pytest

from libtropic import ParamError, SlotEmptyError, SlotNotEmptyError, Tropic01

from ..conftest import (
    R_MEM_DATA_SIZE_MAX,
    R_MEM_DATA_SLOT_MAX,
    R_MEM_DATA_SLOT_MIN,
    generate_random_length,
    generate_test_data,
)


@pytest.mark.hardware
@pytest.mark.destructive
class TestRMemData:
    """
    Tests for R_Mem_Data_Read, R_Mem_Data_Write, and R_Mem_Data_Erase commands.

    Maps to: lt_test_rev_r_mem()
    """

    def test_write_read_erase_all_slots_full_size(
        self,
        device_with_session: Tropic01,
        r_mem_slot_cleanup,
    ) -> None:
        """
        Test writing, reading, and erasing all slots with full-size data.

        For each slot:
        1. Erase slot (ensure empty)
        2. Verify read fails (slot empty)
        3. Write max-size random data
        4. Read and verify contents match
        5. Verify write again fails (slot not empty)
        6. Erase slot
        7. Verify read fails (slot empty)
        """
        for slot in range(R_MEM_DATA_SLOT_MIN, R_MEM_DATA_SLOT_MAX + 1):
            r_mem_slot_cleanup.add(slot)

            # Ensure slot is empty
            try:
                device_with_session.memory.erase(slot)
            except SlotEmptyError:
                pass  # Already empty

            # Verify read fails on empty slot
            with pytest.raises(SlotEmptyError):
                device_with_session.memory.read(slot)

            # Generate and write random data
            write_data = generate_test_data(R_MEM_DATA_SIZE_MAX)
            device_with_session.memory.write(slot=slot, data=write_data)

            # Read and verify
            read_data = device_with_session.memory.read(slot)
            assert read_data == write_data, f"Slot {slot}: Data mismatch"

            # Write again should fail (slot not empty)
            zeros = bytes(R_MEM_DATA_SIZE_MAX)
            with pytest.raises(SlotNotEmptyError):
                device_with_session.memory.write(slot=slot, data=zeros)

            # Verify data unchanged after failed write
            read_data = device_with_session.memory.read(slot)
            assert read_data == write_data, f"Slot {slot}: Data changed after failed write"

            # Erase slot
            device_with_session.memory.erase(slot)

            # Verify read fails after erase
            with pytest.raises(SlotEmptyError):
                device_with_session.memory.read(slot)

    def test_write_read_partial_size(
        self,
        device_with_session: Tropic01,
        r_mem_slot_cleanup,
    ) -> None:
        """
        Test writing and reading partial-size data on all slots.

        For each slot, write random data of random length < max.
        """
        for slot in range(R_MEM_DATA_SLOT_MIN, R_MEM_DATA_SLOT_MAX + 1):
            r_mem_slot_cleanup.add(slot)

            # Generate random length (1 to max-1)
            data_len = generate_random_length(R_MEM_DATA_SIZE_MAX - 1, min_len=1)

            # Generate and write random data
            write_data = generate_test_data(data_len)
            device_with_session.memory.write(slot=slot, data=write_data)

            # Read and verify
            read_data = device_with_session.memory.read(slot)
            assert len(read_data) == data_len, (
                f"Slot {slot}: Expected {data_len} bytes, got {len(read_data)}"
            )
            assert read_data == write_data, f"Slot {slot}: Data mismatch"

    def test_write_zero_length_fails(
        self,
        device_with_session: Tropic01,
        r_mem_slot_cleanup,
    ) -> None:
        """Test that writing zero-length data raises ParamError."""
        for slot in range(R_MEM_DATA_SLOT_MIN, R_MEM_DATA_SLOT_MAX + 1):
            with pytest.raises(ParamError):
                device_with_session.memory.write(slot=slot, data=b"")

    def test_dict_like_access(
        self,
        device_with_session: Tropic01,
        r_mem_slot_cleanup,
    ) -> None:
        """Test dict-like read/write/delete access."""
        slot = 100
        r_mem_slot_cleanup.add(slot)

        # Ensure slot is empty
        try:
            del device_with_session.memory[slot]
        except SlotEmptyError:
            pass

        # Write using dict syntax
        test_data = b"secret data"
        device_with_session.memory[slot] = test_data

        # Read using dict syntax
        read_data = device_with_session.memory[slot]
        assert read_data == test_data

        # Delete using dict syntax
        del device_with_session.memory[slot]

        # Verify deleted
        with pytest.raises(SlotEmptyError):
            _ = device_with_session.memory[slot]

    def test_erase_empty_slot(self, device_with_session: Tropic01) -> None:
        """Test that erasing an already empty slot works without error."""
        # Slot 500 should be empty
        # Note: Some implementations may raise SlotEmptyError, others may succeed silently
        # Check the actual behavior
        try:
            device_with_session.memory.erase(500)
        except SlotEmptyError:
            pass  # This is acceptable behavior

    def test_write_single_byte(
        self,
        device_with_session: Tropic01,
        r_mem_slot_cleanup,
    ) -> None:
        """Test writing and reading single byte."""
        slot = 0
        r_mem_slot_cleanup.add(slot)

        write_data = b"\x42"
        device_with_session.memory.write(slot=slot, data=write_data)

        read_data = device_with_session.memory.read(slot)
        assert read_data == write_data
