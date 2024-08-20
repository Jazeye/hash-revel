# Hash Cracking Tool

This script is a simple hash cracking tool that identifies hash types and attempts to crack them using a recommended wordlist. It supports multiple hash types, including MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, scrypt, PBKDF2, and Argon2.

## Features

* **Hash Identification**: Automatically detects the type of hash based on its length and pattern.
* **Wordlist Selection**: Chooses an appropriate wordlist based on the hash type and complexity level.
* **Hash Cracking**: Uses hashcat to attempt to crack the hash using the selected wordlist.

## Usage

To use the script, run it with the hash you want to crack and the complexity level of the password.

 ```bash
./hash_cracking_tool.sh <hash> <complexity>
 ```
 
## Parameters

* `<hash>`: The hash you want to crack (e.g., MD5, SHA1, etc.)
* `<complexity>`: The complexity level of the password. Determines which wordlist will be used.

## Complexity Levels

* 1-5: Basic wordlists (shorter lists)
* 6-10: Intermediate wordlists (medium-length lists)
* 11+: Advanced wordlists (longer and more comprehensive lists)

## Example

To crack an MD5 hash with complexity level 8:

 ```bash
./hash_cracking_tool.sh d41d8cd98f00b204e9800998ecf8427e 8
 ```
 
## Dependencies

* **hashcat**: This script uses hashcat for cracking hashes. Make sure it is installed and available in your PATH.
* **curl**: Used for downloading wordlists.

## Installation

1. Clone the repository:

 ```bash
git clone https://github.com/Jazeye/hash-revel.git
 ```
2. Navigate to the directory:

  ```bash
  cd hashrev
  ```
3. Make the script executable:
 ```bash
 chmod +x hashrev.sh
 ```

 4. Install Dependencies:

Make sure hashcat and curl are installed on your system. You can install them using your package manager.

**On Debian/Ubuntu:**

 ```bash
sudo apt-get install hashcat curl
 ```
 **On Red Hat/CentOS:**

  ```bash
 sudo yum install hashcat curl
 ```