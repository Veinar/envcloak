"""
constants.py

This module defines constants used throughout the `envcloak` package.
It centralizes configuration and default values to ensure consistency and easier maintenance.
"""

# AES Encryption
AES_BLOCK_SIZE = 128  # Block size for AES
NONCE_SIZE = 12  # Recommended size for GCM nonce
KEY_SIZE = 32  # 256-bit key

# Key Derivation
SALT_SIZE = 16  # Salt size for key derivation
