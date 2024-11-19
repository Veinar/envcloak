import os
import click
from .encryptor import encrypt_file, decrypt_file, derive_key

@click.group()
def main():
    """
    EnvCloak: Securely manage encrypted environment variables.
    """
    pass


@click.command()
@click.option(
    "--input", "-i", required=True, help="Path to the input file (e.g., .env)."
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Path to the output encrypted file (e.g., .env.enc).",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the encryption key file."
)
def encrypt(input, output, key_file):
    """
    Encrypt environment variables from a file.
    """
    with open(key_file, "rb") as kf:
        key = kf.read()
    encrypt_file(input, output, key)
    click.echo(f"File {input} encrypted -> {output} using key {key_file}")


@click.command()
@click.option(
    "--input",
    "-i",
    required=True,
    help="Path to the encrypted input file (e.g., .env.enc).",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Path to the output decrypted file (e.g., .env).",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the decryption key file."
)
def decrypt(input, output, key_file):
    """
    Decrypt environment variables from a file.
    """
    with open(key_file, "rb") as kf:
        key = kf.read()
    decrypt_file(input, output, key)
    click.echo(f"File {input} decrypted -> {output} using key {key_file}")


@click.command()
@click.option(
    "--output", "-o", required=True, help="Path to save the generated encryption key."
)
def generate_key(output):
    """
    Generate a new encryption key.
    """
    key = os.urandom(32)  # Generate a 256-bit random key
    with open(output, "wb") as key_file:
        key_file.write(key)
    click.echo(f"Encryption key generated and saved to {output}")


@click.command()
@click.option(
    "--password", "-p", required=True, help="Password to derive the encryption key."
)
@click.option(
    "--salt", "-s", required=False, help="Salt for key derivation (16 bytes as hex)."
)
@click.option(
    "--output", "-o", required=True, help="Path to save the derived encryption key."
)
def generate_key_from_password(password, output, salt=None):
    """
    Derive an encryption key from a password and salt.
    """
    if len(salt) != 32:  # Hex-encoded salt should be 16 bytes
        raise click.BadParameter("Salt must be 16 bytes (32 hex characters).")
    
    if salt is None:
        salt_bytes = None
    else:
        salt_bytes = bytes.fromhex(salt)
    key = derive_key(password, salt_bytes)
    with open(output, "wb") as key_file:
        key_file.write(key)
    click.echo(f"Derived encryption key saved to {output}")


@click.command()
@click.option(
    "--input", "-i", required=True, help="Path to the encrypted file to re-encrypt."
)
@click.option(
    "--old-key-file", "-ok", required=True, help="Path to the old encryption key."
)
@click.option(
    "--new-key-file", "-nk", required=True, help="Path to the new encryption key."
)
@click.option("--output", "-o", required=True, help="Path to the re-encrypted file.")
def rotate_keys(input, old_key_file, new_key_file, output):
    """
    Rotate encryption keys by re-encrypting a file with a new key.
    """
    with open(old_key_file, "rb") as okf:
        old_key = okf.read()
    with open(new_key_file, "rb") as nkf:
        new_key = nkf.read()
    # Decrypt with old key and re-encrypt with new key
    temp_decrypted = f"{output}.tmp"
    decrypt_file(input, temp_decrypted, old_key)
    encrypt_file(temp_decrypted, output, new_key)
    os.remove(temp_decrypted)  # Clean up temporary file
    click.echo(f"Keys rotated for {input} -> {output}")


# Add all commands to the main group
main.add_command(encrypt)
main.add_command(decrypt)
main.add_command(generate_key)
main.add_command(generate_key_from_password)
main.add_command(rotate_keys)


if __name__ == "__main__":
    main()
