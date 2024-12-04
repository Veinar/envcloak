"""
exceptions.py

This module defines custom exception classes for handling errors specific to the `envcloak` package.
It enhances error reporting with meaningful context, aiding debugging and user feedback.
"""


#### EncryptedEnvLoader Exceptions
class EncryptedEnvLoaderException(Exception):
    """Base exception for EncryptedEnvLoader errors."""

    default_message = "An error occurred in EncryptedEnvLoader."

    def __init__(self, message=None, details=None):
        self.message = message or self.default_message
        self.details = details
        super().__init__(self.message)

    def __str__(self):
        error_message = f"Error: {self.message}"
        if self.details:
            error_message += f"\nDetails: {self.details}"
        return error_message


class KeyFileNotFoundException(EncryptedEnvLoaderException):
    """Raised when the key file is not found."""

    default_message = "Key file not found."


class EncryptedFileNotFoundException(EncryptedEnvLoaderException):
    """Raised when the encrypted file is not found."""

    default_message = "Encrypted file not found."


class FileDecryptionException(EncryptedEnvLoaderException):
    """Raised when file decryption fails."""

    default_message = "Failed to decrypt the file."


class UnsupportedFileFormatException(EncryptedEnvLoaderException):
    """Raised when the file format is unsupported."""

    default_message = "Unsupported file format detected."


class DirectoryEmptyException(EncryptedEnvLoaderException):
    """Raised when an input directory is empty."""

    default_message = "The provided input directory is empty."


class OutputFileExistsException(EncryptedEnvLoaderException):
    """Raised when the output file already exists and may be overwritten."""

    default_message = (
        "The output file or directory already exists and will be overwritten."
    )


class DiskSpaceException(EncryptedEnvLoaderException):
    """Raised when there is insufficient disk space."""

    default_message = "Insufficient disk space available for this operation."


#### Cryptography Exceptions
class CryptographyException(Exception):
    """Base exception for cryptographic errors."""

    default_message = "An error occurred during a cryptographic operation."

    def __init__(self, message=None, details=None):
        self.message = message or self.default_message
        self.details = details
        super().__init__(self.message)

    def __str__(self):
        error_message = f"Error: {self.message}"
        if self.details:
            error_message += f"\nDetails: {self.details}"
        return error_message


class InvalidSaltException(CryptographyException):
    """Raised when an invalid salt is provided."""

    default_message = (
        "The provided salt is invalid. It must be exactly the required size."
    )


class InvalidKeyException(CryptographyException):
    """Raised when an invalid encryption key is provided."""

    default_message = (
        "The provided encryption key is invalid. It must match the required size."
    )


class EncryptionException(CryptographyException):
    """Raised when encryption fails."""

    default_message = "Failed to encrypt the data."


class DecryptionException(CryptographyException):
    """Raised when decryption fails."""

    default_message = "Failed to decrypt the data."


class FileEncryptionException(CryptographyException):
    """Raised when file encryption fails."""

    default_message = "Failed to encrypt the file."


#### Integrity exceptions
class IntegrityCheckFailedException(CryptographyException):
    """Raised when the integrity check of a file fails."""

    default_message = (
        "Integrity check failed! The file may have been tampered with or corrupted."
    )

    def __init__(self, message=None, details=None):
        self.message = message or self.default_message
        self.details = details
        super().__init__(self.message)

    def __str__(self):
        error_message = f"Error: {self.message}"
        if self.details:
            error_message += f"\nDetails: {self.details}"
        return error_message
