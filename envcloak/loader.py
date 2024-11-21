import os
import json
from pathlib import Path
import yaml
from dotenv import dotenv_values
from defusedxml.ElementTree import parse as safe_parse
from envcloak.encryptor import decrypt_file


class EncryptedEnvLoader:
    def __init__(self, file_path: str, key_file: str):
        """
        Initialize the EncryptedEnvLoader with an encrypted file and key file.
        :param file_path: Path to the encrypted environment variables file.
        :param key_file: Path to the encryption key file.
        """
        self.file_path = Path(file_path)
        self.key_file = Path(key_file)
        self.decrypted_data = None

    def load(self):
        """
        Load and decrypt the environment variables file.
        """
        # Read the key
        with open(self.key_file, "rb") as kf:
            key = kf.read()

        # Decrypt the file to a temporary file with the same extension
        temp_decrypted_path = self.file_path.with_suffix(self.file_path.suffix + ".tmp")
        decrypt_file(self.file_path, temp_decrypted_path, key)

        # Detect file format and parse it
        self.decrypted_data = self._parse_file(temp_decrypted_path)

        # Clean up the temporary file
        os.remove(temp_decrypted_path)

        return self

    def _parse_file(self, file_path: Path):
        """
        Detect the format of the decrypted file and parse it into a dictionary.
        :param file_path: Path to the decrypted file.
        :return: Dictionary of environment variables.
        """
        cleaned_suffix = file_path.name.replace(".enc", "").replace(".tmp", "")
        base_suffix = Path(cleaned_suffix).suffix

        if base_suffix in {".json"}:  # JSON
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        elif base_suffix in {".yaml", ".yml"}:  # YAML
            with open(file_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        elif base_suffix in {".xml"}:  # XML
            return self._parse_xml(file_path)
        elif base_suffix in {".env", ""}:  # Plaintext
            return dotenv_values(file_path)
        else:
            raise ValueError(f"Unsupported file format after cleaning: {base_suffix}")

    def _parse_xml(self, file_path: Path):
        """
        Parse an XML file into a dictionary of environment variables.
        :param file_path: Path to the XML file.
        :return: Dictionary of environment variables.
        """
        tree = safe_parse(file_path)
        root = tree.getroot()
        env_dict = {}
        for child in root:
            env_dict[child.tag] = child.text
        return env_dict

    def to_os_env(self):
        """
        Load decrypted environment variables into os.environ.
        """
        if not self.decrypted_data:
            raise ValueError("Decrypted data is not loaded. Call `load()` first.")

        for key, value in self.decrypted_data.items():
            os.environ[key] = value

        return self


# Wrapper function for convenience
def load_encrypted_env(file_path: str, key_file: str) -> EncryptedEnvLoader:
    """
    Load an encrypted environment variables file and prepare it for use.
    :param file_path: Path to the encrypted environment variables file.
    :param key_file: Path to the encryption key file.
    :return: EncryptedEnvLoader instance
    """
    loader = EncryptedEnvLoader(file_path, key_file)
    loader.load()  # Automatically load decrypted data
    return loader
