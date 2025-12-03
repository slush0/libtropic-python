# C SDK Parity Reference

Quick reference for developers familiar with the libtropic C SDK.

## API Mapping (Python → C)

```
Tropic01.open() / with Tropic01()     → lt_init(h)
device.close()                        → lt_deinit(h)
device.mode                           → lt_get_tr01_mode()
device.get_chip_id()                  → lt_get_info_chip_id()
device.get_riscv_firmware_version()   → lt_get_info_riscv_fw_ver()
device.get_spect_firmware_version()   → lt_get_info_spect_fw_ver()
device.get_firmware_header(bank)      → lt_get_info_fw_bank()
device.get_certificate_store()        → lt_get_info_cert_store()
device.get_device_public_key()        → lt_get_st_pub()

device.start_session(...)             → lt_session_start()
device.abort_session()                → lt_session_abort()
device.verify_chip_and_start_session()→ lt_verify_chip_and_start_secure_session()

device.reboot(mode)                   → lt_reboot()
device.sleep()                        → lt_sleep()
device.ping(data)                     → lt_ping()
device.get_log()                      → lt_get_log_req()

device.ecc.generate(slot, curve)      → lt_ecc_key_generate()
device.ecc.store(slot, curve, key)    → lt_ecc_key_store()
device.ecc.read(slot)                 → lt_ecc_key_read()
device.ecc.erase(slot)                → lt_ecc_key_erase()
device.ecc.sign_ecdsa(slot, message)  → lt_ecc_ecdsa_sign()
device.ecc.sign_eddsa(slot, message)  → lt_ecc_eddsa_sign()

device.random.get_bytes(count)        → lt_random_value_get()

device.memory.write(slot, data)       → lt_r_mem_data_write()
device.memory.read(slot)              → lt_r_mem_data_read()
device.memory.erase(slot)             → lt_r_mem_data_erase()

device.config.write_r(address, value) → lt_r_config_write()
device.config.read_r(address)         → lt_r_config_read()
device.config.erase_r()               → lt_r_config_erase()
device.config.write_i_bit(addr, bit)  → lt_i_config_write()
device.config.read_i(address)         → lt_i_config_read()
device.config.read_all_r()            → lt_read_whole_R_config()
device.config.write_all_r(config)     → lt_write_whole_R_config()
device.config.read_all_i()            → lt_read_whole_I_config()
device.config.write_all_i(config)     → lt_write_whole_I_config()

device.counters.init(index, value)    → lt_mcounter_init()
device.counters.update(index)         → lt_mcounter_update()
device.counters.get(index)            → lt_mcounter_get()

device.mac_and_destroy.execute(slot, data) → lt_mac_and_destroy()

device.pairing_keys.write(slot, key)  → lt_pairing_key_write()
device.pairing_keys.read(slot)        → lt_pairing_key_read()
device.pairing_keys.invalidate(slot)  → lt_pairing_key_invalidate()

device.firmware.update(firmware_data) → lt_do_mutable_fw_update() [ACAB only]
```

## Type Mapping

| Python | C |
|--------|---|
| `ReturnCode` | `lt_ret_t` |
| `DeviceMode` | `lt_tr01_mode_t` |
| `StartupMode` | `lt_startup_id_t` |
| `EccCurve` | `lt_ecc_curve_type_t` |
| `EccKeyOrigin` | `lt_ecc_key_origin_t` |
| `FirmwareBank` | `lt_bank_id_t` |
| `PairingKeySlot` | `lt_pkey_index_t` |
| `EccSlot` | `lt_ecc_slot_t` |
| `McounterIndex` | `lt_mcounter_index_t` |
| `MacAndDestroySlot` | `lt_mac_and_destroy_slot_t` |
| `ConfigAddress` | `lt_config_obj_addr_t` |
| `CertKind` | `lt_cert_kind_t` |
| `ChipId` | `lt_chip_id_t` |
| `SerialNumber` | `lt_ser_num_t` |
| `CertificateStore` | `lt_cert_store_t` |
| `DeviceConfig` | `lt_config_t` |
| `FirmwareHeader` | `lt_header_boot_v1_t` / `lt_header_boot_v2_t` |

## Key Differences

### Error Handling

C returns `lt_ret_t`, Python raises exceptions:

```python
TropicError           # Base (LT_FAIL)
├── NoSessionError    # LT_HOST_NO_SESSION
├── ParamError        # LT_PARAM_ERR
├── CryptoError       # LT_CRYPTO_ERR
├── DeviceAlarmError  # LT_L1_CHIP_ALARM_MODE
├── UnauthorizedError # LT_L3_UNAUTHORIZED
├── SlotEmptyError    # LT_L3_SLOT_EMPTY
├── SlotNotEmptyError # LT_L3_SLOT_NOT_EMPTY
├── SlotExpiredError  # LT_L3_SLOT_EXPIRED
├── SlotInvalidError  # LT_L3_SLOT_INVALID
├── InvalidKeyError   # LT_L3_INVALID_KEY
├── CounterInvalidError # LT_L3_COUNTER_INVALID
├── HardwareError     # LT_L3_HARDWARE_FAIL
├── HandshakeError    # LT_L2_HSK_ERR
├── AuthenticationError # LT_L2_TAG_ERR
├── CrcError          # LT_L2_CRC_ERR
├── CertificateError  # LT_CERT_*
└── RebootError       # LT_REBOOT_UNSUCCESSFUL
```

### Transport Layer

- **C**: Compile-time HAL selection (`hal/posix/`, `hal/linux/`)
- **Python**: Runtime selection via `UsbDongleTransport` or `LinuxSpiTransport`

### Default Pairing Keys

C globals are in `libtropic.keys` module:

| C | Python |
|---|--------|
| `sh0priv_eng_sample[]` | `keys.SH0_PRIV_ENG_SAMPLE` |
| `sh0pub_eng_sample[]` | `keys.SH0_PUB_ENG_SAMPLE` |
| `sh0priv_prod0[]` | `keys.SH0_PRIV_PROD` |
| `sh0pub_prod0[]` | `keys.SH0_PUB_PROD` |

## Not Implemented / Incompatible

### ABAB Silicon (Not Supported)

Python targets ACAB silicon only. These ABAB-specific functions are not implemented:

- `lt_mutable_fw_erase()` — not needed for ACAB firmware update flow

### Partial Enum Coverage

`MacAndDestroySlot` only defines slots 0-15. Use raw integers for slots 16-127:

```python
device.mac_and_destroy.execute(slot=64, data=input_data)  # Works with int
```

### Helper Functions (Not Needed)

These C helpers have no direct equivalent (Python built-ins suffice):

| C | Python Alternative |
|---|-------------------|
| `lt_ret_verbose()` | Exception messages |
| `lt_print_bytes()` | `bytes.hex()` |
| `lt_print_chip_id()` | `print(chip_id)` via `__str__` |
| `lt_print_fw_header()` | `print(header)` via `__str__` |
| `cfg_desc_table[]` | `ConfigAddress.UAP_PING.name` |
