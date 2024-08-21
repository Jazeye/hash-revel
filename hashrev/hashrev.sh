#!/bin/bash
# Landing screen
echo "====================================="
echo "   Hash Identifier and Cracker  "
echo "   Developed by: Jassel"
echo "   Version: 0.1"
echo "====================================="
echo ""

# Define a function to identify the hash type
identify_hash() {
  local hash=$1
  local hash_type="unknown"

  # Check for MD5 hash
  if [[ ${hash:0:32} =~ ^[a-f0-9]{32}$ ]]; then
    hash_type="MD5"
  # Check for SHA1 hash
  elif [[ ${hash:0:40} =~ ^[a-f0-9]{40}$ ]]; then
    hash_type="SHA1"
  # Check for SHA256 hash
  elif [[ ${hash:0:64} =~ ^[a-f0-9]{64}$ ]]; then
    hash_type="SHA256"
  # Check for SHA512 hash
  elif [[ ${hash:0:128} =~ ^[a-f0-9]{128}$ ]]; then
    hash_type="SHA512"
  # Check for NTLM hash
  elif [[ ${hash:0:32} =~ ^[a-f0-9]{32}$ ]] && [[ ${hash:32:32} =~ ^[a-f0-9]{32}$ ]]; then
    hash_type="NTLM"
  # Check for LM hash
  elif [[ ${hash:0:32} =~ ^[a-f0-9]{32}$ ]] && [[ ${hash:32:32} =~ ^[a-f0-9]{32}$ ]] && [[ ${hash:64:32} =~ ^[a-f0-9]{32}$ ]]; then
    hash_type="LM"
  # Check for bcrypt hash
  elif [[ ${hash:0:60} =~ ^\$2[abxy]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$ ]]; then
    hash_type="bcrypt"
  # Check for scrypt hash
  elif [[ ${hash:0:60} =~ ^\$s2\$[0-9]{2}\$[a-zA-Z0-9./]{53}$ ]]; then
    hash_type="scrypt"
  # Check for PBKDF2 hash
  elif [[ ${hash:0:60} =~ ^\$pbkdf2-sha1\$[0-9]{2}\$[a-zA-Z0-9./]{53}$ ]]; then
    hash_type="PBKDF2"
  # Check for Argon2 hash
  elif [[ ${hash:0:60} =~ ^\$argon2id\$[0-9]{2}\$[a-zA-Z0-9./]{53}$ ]]; then
    hash_type="Argon2"
  # Check for other hash types (e.g. Whirlpool, Tiger, etc.)
  else
    # Use a tool like hash-identifier to identify the hash type
    hash_type=$(hash-identifier $hash | awk '{print $2}')
  fi

  echo $hash_type
}

# Define a function to select the best wordlist based on the hash type and complexity
select_wordlist() {
  local hash_type=$1
  local complexity=$2
  local wordlist=""

  case $hash_type in
    MD5)
      if [ $complexity -le 5 ]; then
        wordlist="https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt"
      elif [ $complexity -le 10 ]; then
        wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
      else
        wordlist="https://raw.githubusercontent.com/hashkiller/hashkiller.github.io/master/wordlists/100-million-passwords.txt"
      fi
      ;;
    SHA1)
      if [ $complexity -le 5 ]; then
        wordlist="https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt"
      elif [ $complexity -le 10 ]; then
        wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
      else
        wordlist="https://raw.githubusercontent.com/openwall/john/master/src/wordlists/password.lst"
      fi
      ;;
    SHA256)
      if [ $complexity -le 5 ]; then
        wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
      elif [ $complexity -le 10 ]; then
        wordlist="https://raw.githubusercontent.com/hashkiller/hashkiller.github.io/master/wordlists/100-million-passwords.txt"
      else
        wordlist="https://raw.githubusercontent.com/openwall/john/master/src/wordlists/password.lst"
      fi
      ;;
    SHA512)
      if [ $complexity -le 5 ]; then
        wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
      elif [ $complexity -le 10 ]; then
        wordlist="https://raw.githubusercontent.com/hashkiller/hashkiller.github.io/master/wordlists/100-million-passwords.txt"
      else
        wordlist="https://raw.githubusercontent.com/openwall/john/master/src/wordlists/password.lst"
      fi
      ;;
    NTLM)
      if [ $complexity -le 5 ]; then
        wordlist="https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt"
      elif [ $complexity -le 10 ]; then
        wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
      else
        wordlist="https://raw.githubusercontent.com/hashkiller/hashkiller.github.io/master/wordlists/100-million-passwords.txt"
      fi
      ;;
    bcrypt|scrypt|PBKDF2|Argon2)
      wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt"
      ;;
    *)
      wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
      ;;
  esac

  echo $wordlist
}

# Define a function to crack the hash using hashcat
crack_hash() {
  local hash=$1
  local hash_type=$2
  local wordlist_file=$3

  # Download the wordlist
  wordlist_path=$(basename $wordlist_file)
  if [ ! -f $wordlist_path ]; then
    echo "Downloading wordlist..."
    curl -O $wordlist_file
  fi

  # Determine the hashcat mode based on the hash type
  local hashcat_mode=""

  case $hash_type in
    MD5) hashcat_mode=0 ;;
    SHA1) hashcat_mode=100 ;;
    SHA256) hashcat_mode=1400 ;;
    SHA512) hashcat_mode=1700 ;;
    NTLM) hashcat_mode=1000 ;;
    bcrypt) hashcat_mode=3200 ;;
    scrypt) hashcat_mode=8900 ;;
    PBKDF2) hashcat_mode=12000 ;;
    Argon2) hashcat_mode=13300 ;;
    *) echo "Unsupported hash type for cracking: $hash_type"; return ;;
  esac

  # Attempt to crack the hash
  echo "Attempting to crack $hash_type hash..."
  hashcat -m $hashcat_mode -a 0 -o cracked.txt --force <<< "$hash" $wordlist_path

  if [ -f cracked.txt ]; then
    echo "Hash cracked successfully!"
    cat cracked.txt
  else
    echo "Failed to crack the hash."
  fi
}

# Display complexity levels
echo "Complexity Levels:"
echo "1-5: Basic wordlists (shorter lists)"
echo "6-10: Intermediate wordlists (medium-length lists)"
echo "11+: Advanced wordlists (longer and more comprehensive lists)"
echo ""

# Main script logic
if [ $# -lt 2 ]; then
  echo "Usage: $0 <hash> <complexity>"
  echo "Example: $0 d41d8cd98f00b204e9800998ecf8427e 8"
  exit 1
fi

hash=$1
complexity=$2

hash_type=$(identify_hash $hash)
wordlist=$(select_wordlist $hash_type $complexity)

echo "Hash Type: $hash_type"
echo "Recommended Wordlist: $wordlist"

# Prompt the user if they want to crack the hash
read -p "Do you want to attempt to crack the hash? (y/n): " crack_choice

if [[ $crack_choice == "y" || $crack_choice == "Y" ]]; then
  crack_hash $hash $hash_type $wordlist
fi
