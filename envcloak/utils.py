from pathlib import Path


def add_to_gitignore(directory: str, filename: str):
    """
    Add a filename to the .gitignore file in the specified directory.

    :param directory: Directory where the .gitignore file is located.
    :param filename: Name of the file to add to .gitignore.
    """
    gitignore_path = Path(directory) / ".gitignore"

    if gitignore_path.exists():
        # Append the filename if not already listed
        with open(gitignore_path, "r+", encoding="utf-8") as gitignore_file:
            content = gitignore_file.read()
            if filename not in content:
                gitignore_file.write(f"\n{filename}")
                print(f"Added '{filename}' to {gitignore_path}")
    else:
        # Create a new .gitignore file and add the filename
        with open(gitignore_path, "w", encoding="utf-8") as gitignore_file:
            gitignore_file.write(f"{filename}\n")
        print(f"Created {gitignore_path} and added '{filename}'")
