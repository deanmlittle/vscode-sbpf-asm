# Change Log

All notable changes to the "sbpf-assembly" extension will be documented in this file.

Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

## [Unreleased]

### Changed
- Added autocomplete and hover metadata for sol_sha512, sol_curve_decompress, sol_get_sysvar, sol_get_epoch_stake, and sol_panic_
- Updated syscall signatures for sol_get_return_data and sol_get_processed_sibling_instruction

## [0.0.5] - 2025-08-26

### Changed
- Removed diagnostic errors for missing entrypoint labels and `.globl entrypoint` declarations
- Merged autocomplete for call/jump targets
- Merged tooltip option