# Hash Cracking Tool

This script is a simple hash cracking tool that identifies hash types and attempts to crack them using a recommended wordlist. It supports multiple hash types, including MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, scrypt, PBKDF2, Argon2, and various Django and Drupal hashes.

## Features

- **Hash Identification**: Automatically detects the type of hash based on its length and pattern.
- **Wordlist Selection**: Chooses an appropriate wordlist based on the hash type and complexity level.
- **Hash Cracking**: Attempts to crack the hash using the selected wordlist.
- **Animation**: Displays a simple animation to indicate cracking progress.

## Usage

To use the script, run it with the hash you want to crack and the complexity level of the password.

```bash
python hash_cracking_tool.py
```
## Parameters

- <hash>: The hash you want to crack (e.g., MD5, SHA1, etc.)
- <complexity>: The complexity level of the password, which determines the wordlist used.

## Complexity Levels
- 1-5: Basic wordlists (shorter lists)
- 6-10: Intermediate wordlists (medium-length lists)
- 11+: Advanced wordlists (longer and more comprehensive lists)

## Example
To crack a hash with complexity level 8, run the script and follow the prompts.

## Dependencies
- requests: For fetching wordlists from URLs.
- bcrypt: For verifying bcrypt hashes.
- scrypt: For verifying scrypt hashes.
- passlib: For verifying PBKDF2 and Argon2 hashes.

## Installation
Clone the repository:

```bash
git clone https://github.com/Jazeye/hash-revel.git
```
## Navigate to the directory:

```bash
cd hash-revel
```

## Install Python dependencies:

Install the required Python modules using pip:

```bash
pip install -r requirements.txt
```
- Ensure you have Python installed on your system. The script requires Python 3.6 or higher.

## Script Overview
# Landing Screen
Displays a landing page with information about the script and complexity levels.

# Identify Hash
Detects the hash type based on its length and pattern.

# Select Wordlist
Chooses an appropriate wordlist based on the complexity level:

- Basic: Uses a predefined list of common passwords.
- Intermediate: Fetches a wordlist from a URL.
- Advanced: Fetches a wordlist from a URL.

## Crack Hash
Attempts to crack the hash using the selected wordlist. Supports MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, NTLM, bcrypt, scrypt, PBKDF2, Argon2, and various Django and Drupal hashes.

License
This project is licensed under the MIT License. See the LICENSE file for details.

