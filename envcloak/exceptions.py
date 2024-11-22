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


#### Cryptography exceptions


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
