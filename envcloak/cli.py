import os
from pathlib import Path
import shutil
import click
from click import style
from envcloak.encryptor import encrypt_file, decrypt_file
from envcloak.generator import generate_key_file, generate_key_from_password_file
from envcloak.utils import add_to_gitignore, calculate_required_space
from envcloak.validation import (
    check_file_exists,
    check_directory_exists,
    check_directory_not_empty,
    check_output_not_exists,
    check_permissions,
    check_disk_space,
    validate_salt,
)
from envcloak.exceptions import (
    OutputFileExistsException,
    DiskSpaceException,
    InvalidSaltException,
    FileEncryptionException,
    FileDecryptionException,
)


@click.group()
@click.version_option(prog_name="EnvCloak")
def main():
    """
    EnvCloak: Securely manage encrypted environment variables.
    """
    # No unnecessary pass here


@click.command()
@click.option(
    "--input", "-i", required=False, help="Path to the input file (e.g., .env)."
)
@click.option(
    "--directory",
    "-d",
    required=False,
    help="Path to the directory of files to encrypt.",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Path to the output file or directory for encrypted files.",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the encryption key file."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
@click.option(
    "--force",
    is_flag=True,
    help="Force overwrite of existing encrypted files or directories.",
)
def encrypt(input, directory, output, key_file, dry_run, force):
    """
    Encrypt environment variables from a file or all files in a directory.
    """
    try:
        # Always perform validation
        if not input and not directory:
            raise click.UsageError("You must provide either --input or --directory.")
        if input and directory:
            raise click.UsageError(
                "You must provide either --input or --directory, not both."
            )
        if input:
            check_file_exists(input)
            check_permissions(input)
        if directory:
            check_directory_exists(directory)
            check_directory_not_empty(directory)
        check_file_exists(key_file)
        check_permissions(key_file)

        # Handle overwrite with --force
        if not force:
            check_output_not_exists(output)
        else:
            if os.path.exists(output):
                click.echo(
                    style(
                        f"⚠️  Warning: Overwriting existing file or directory {output} (--force used).",
                        fg="yellow",
                    )
                )
                if os.path.isdir(output):
                    shutil.rmtree(output)  # Remove existing directory
                else:
                    os.remove(output)  # Remove existing file

        required_space = calculate_required_space(input, directory)
        check_disk_space(output, required_space)

        if dry_run:
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual encryption logic
        with open(key_file, "rb") as kf:
            key = kf.read()

        if input:
            encrypt_file(input, output, key)
            click.echo(f"File {input} encrypted -> {output} using key {key_file}")
        elif directory:
            input_dir = Path(directory)
            output_dir = Path(output)
            if not output_dir.exists():
                output_dir.mkdir(parents=True)

            for file in input_dir.iterdir():
                if file.is_file():  # Skip directories
                    output_file = output_dir / (file.name + ".enc")
                    encrypt_file(str(file), str(output_file), key)
                    click.echo(
                        f"File {file} encrypted -> {output_file} using key {key_file}"
                    )
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileEncryptionException,
    ) as e:
        click.echo(f"Error during encryption: {str(e)}")


@click.command()
@click.option(
    "--input",
    "-i",
    required=False,
    help="Path to the encrypted input file (e.g., .env.enc).",
)
@click.option(
    "--directory",
    "-d",
    required=False,
    help="Path to the directory of encrypted files.",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Path to the output file or directory for decrypted files.",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the decryption key file."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
@click.option(
    "--force",
    is_flag=True,
    help="Force overwrite of existing decrypted files or directories.",
)
def decrypt(input, directory, output, key_file, dry_run, force):
    """
    Decrypt environment variables from a file or all files in a directory.
    """
    try:
        # Always perform validation
        if not input and not directory:
            raise click.UsageError("You must provide either --input or --directory.")
        if input and directory:
            raise click.UsageError(
                "You must provide either --input or --directory, not both."
            )
        if input:
            check_file_exists(input)
            check_permissions(input)
        if directory:
            check_directory_exists(directory)
            check_directory_not_empty(directory)
        check_file_exists(key_file)
        check_permissions(key_file)

        # Handle overwrite with --force
        if not force:
            check_output_not_exists(output)
        else:
            if os.path.exists(output):
                click.echo(
                    style(
                        f"⚠️  Warning: Overwriting existing file or directory {output} (--force used).",
                        fg="yellow",
                    )
                )
                if os.path.isdir(output):
                    shutil.rmtree(output)  # Remove existing directory
                else:
                    os.remove(output)  # Remove existing file

        required_space = calculate_required_space(input, directory)
        check_disk_space(output, required_space)

        if dry_run:
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual decryption logic
        with open(key_file, "rb") as kf:
            key = kf.read()

        if input:
            decrypt_file(input, output, key)
            click.echo(f"File {input} decrypted -> {output} using key {key_file}")
        elif directory:
            input_dir = Path(directory)
            output_dir = Path(output)
            if not output_dir.exists():
                output_dir.mkdir(parents=True)

            for file in input_dir.iterdir():
                if file.is_file() and file.suffix == ".enc":  # Only decrypt .enc files
                    output_file = output_dir / file.stem  # Remove .enc from filename
                    decrypt_file(str(file), str(output_file), key)
                    click.echo(
                        f"File {file} decrypted -> {output_file} using key {key_file}"
                    )
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileDecryptionException,
    ) as e:
        click.echo(f"Error during decryption: {str(e)}")


@click.command()
@click.option(
    "--output", "-o", required=True, help="Path to save the generated encryption key."
)
@click.option(
    "--no-gitignore", is_flag=True, help="Skip adding the key file to .gitignore."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
def generate_key(output, no_gitignore, dry_run):
    """
    Generate a new encryption key.
    """
    try:
        # Always perform validation
        check_output_not_exists(output)
        check_disk_space(output, required_space=32)

        if dry_run:
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual key generation logic
        output_path = Path(output)
        generate_key_file(output_path)
        if not no_gitignore:
            add_to_gitignore(output_path.parent, output_path.name)
    except (OutputFileExistsException, DiskSpaceException) as e:
        click.echo(f"Error during key generation: {str(e)}")


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
@click.option(
    "--no-gitignore", is_flag=True, help="Skip adding the key file to .gitignore."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
def generate_key_from_password(password, salt, output, no_gitignore, dry_run):
    """
    Derive an encryption key from a password and salt.
    """
    try:
        # Always perform validation
        check_output_not_exists(output)
        check_disk_space(output, required_space=32)
        if salt:
            validate_salt(salt)

        if dry_run:
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual key derivation logic
        output_path = Path(output)
        generate_key_from_password_file(password, output_path, salt)
        if not no_gitignore:
            add_to_gitignore(output_path.parent, output_path.name)
    except (OutputFileExistsException, DiskSpaceException, InvalidSaltException) as e:
        click.echo(f"Error during key derivation: {str(e)}")


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
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
def rotate_keys(input, old_key_file, new_key_file, output, dry_run):
    """
    Rotate encryption keys by re-encrypting a file with a new key.
    """
    try:
        # Always perform validation
        check_file_exists(input)
        check_permissions(input)
        check_file_exists(old_key_file)
        check_permissions(old_key_file)
        check_file_exists(new_key_file)
        check_permissions(new_key_file)
        check_output_not_exists(output)
        check_disk_space(output, required_space=1024 * 1024)

        if dry_run:
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual key rotation logic
        with open(old_key_file, "rb") as okf:
            old_key = okf.read()
        with open(new_key_file, "rb") as nkf:
            new_key = nkf.read()

        temp_decrypted = f"{output}.tmp"
        decrypt_file(input, temp_decrypted, old_key)
        encrypt_file(temp_decrypted, output, new_key)
        os.remove(temp_decrypted)  # Clean up temporary file
        click.echo(f"Keys rotated for {input} -> {output}")
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileDecryptionException,
        FileEncryptionException,
    ) as e:
        click.echo(f"Error during key rotation: {str(e)}")


# Add all commands to the main group
main.add_command(encrypt)
main.add_command(decrypt)
main.add_command(generate_key)
main.add_command(generate_key_from_password)
main.add_command(rotate_keys)


if __name__ == "__main__":
    main()
