import hashlib
import requests
import time
import sys
import threading
import bcrypt
import scrypt
from passlib.hash import pbkdf2_sha1, argon2

# Landing screen
def landing_page():
    print("=====================================")
    print("   Hash Identifier and Cracker  ")
    print("   Developed by: Jassel")
    print("   Version: 0.1")
    print("=====================================")
    print("")
    print("Complexity Levels:")
    print("1-5: Basic wordlist (shorter lists)")
    print("6-10: Intermediate wordlists (medium-length lists)")
    print("11+: Advanced wordlists (longer and more comprehensive lists)")
    print("")

# Define a function to identify the hash type
def identify_hash(hash_value):
    hash_type = "Unknown"
    
    if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "MD5"
    elif len(hash_value) == 40 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "SHA1"
    elif len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "SHA256"
    elif len(hash_value) == 128 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "SHA512"
    elif len(hash_value) == 32 and len(hash_value) == 64:
        hash_type = "NTLM"
    elif len(hash_value) == 32 and len(hash_value) == 96:
        hash_type = "LM"
    elif len(hash_value) == 60 and hash_value.startswith("$2"):
        hash_type = "bcrypt"
    elif len(hash_value) == 60 and hash_value.startswith("$s2"):
        hash_type = "scrypt"
    elif len(hash_value) == 60 and hash_value.startswith("$pbkdf2-sha1$"):
        hash_type = "PBKDF2"
    elif len(hash_value) == 60 and hash_value.startswith("$argon2"):
        hash_type = "Argon2"
    elif len(hash_value) == 64 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "SHA3-256"
    elif len(hash_value) == 128 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "SHA3-512"
    elif len(hash_value) == 96 and all(c in '0123456789abcdef' for c in hash_value):
        hash_type = "SHA3-384"
    elif len(hash_value) == 40 and hash_value.startswith("sha1$"):
        hash_type = "Django SHA1"
    elif len(hash_value) == 64 and hash_value.startswith("sha256$"):
        hash_type = "Django SHA256"
    elif len(hash_value) == 128 and hash_value.startswith("sha512$"):
        hash_type = "Django SHA512"
    elif len(hash_value) == 55 and hash_value.startswith("$S$"):
        hash_type = "Drupal SHA512"
    
    return hash_type

# Predefined fast wordlist with 100 common passwords
default_passwords = [
    '123456', 'password', '123456789', '12345678', '12345', '1234567', '1234567890', 'qwerty', 'abc123', 'password1',
    '111111', '123123', 'welcome', 'admin', 'letmein', '1234', 'monkey', 'dragon', 'master', 'trustno1', 
    '123qwe', 'qwertyuiop', 'password123', '1q2w3e4r', 'sunshine', 'princess', '123', '1234qwer', '1234567qwerty', 
    '666666', '7777777', '1qaz2wsx', '654321', 'q1w2e3r4', 'michael', 'superman', 'pokemon', 'asdfghjkl', 'zxcvbnm', 
    '1qazxsw2', 'qwer1234', 'abc1234', 'hello123', 'welcome123', '123456a', '6543210', 'admin123', 'secret', 
    '1qazxsw23edc', 'abcdef', 'p@ssword', 'Password1', 'password!', '1234abcd', 'letmein1', 'Password123', 'qazwsx', 
    'zaq12wsx', 'Qwerty123', '1q2w3e4r5t', 'asdfgh', '123qaz', 'baseball', 'football', 'shadow', '1q2w3e', 'p@ssw0rd',
    '123abc', 'hockey', 'computer', 'maggie', 'iloveyou', '1qazxsw23edc', 'letmein123', 'passw0rd', 'qwe123', 'pa55w0rd', 
    'pa$$word', 'Pa$$w0rd', 'pass123', 'qwerty123', 'summer', 'spring', 'winter', 'autumn', 'qwerty12', 'asdf1234', 
    'asdfg', 'asdfjkl;', 'asdfghj', 'zxcvb', 'zxcvbn', 'zxcvbnm,', 'pass1234', 'Password!', 'Password1!', 'welcome1', 
    'Password!23'
]

# Define a function to select the wordlist based on complexity level
def select_wordlist(complexity):
    if complexity <= 5:
        return default_passwords
    elif complexity <= 10:
        # Using a reliable and working wordlist URL for intermediate complexity
        wordlist_urls = {
            "intermediate": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
        }
        return fetch_wordlist(wordlist_urls["intermediate"])
    else:
        # Using a reliable and working wordlist URL for advanced complexity
        wordlist_urls = {
            "advanced": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        }
        return fetch_wordlist(wordlist_urls["advanced"])

def fetch_wordlist(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"Error fetching wordlist: {e}")
        return []

# Simple animation function
def animate_cracking(stop_event):
    animation = "|/-\\"
    idx = 0
    while not stop_event.is_set():
        time.sleep(0.1)
        sys.stdout.write("\rCracking in progress... " + animation[idx % len(animation)])
        sys.stdout.flush()
        idx += 1

# Define a function to crack the hash
def crack_hash(hash_value, hash_type, wordlist, stop_event):
    print(f"Attempting to crack {hash_type} hash...")

    for word in wordlist:
        if stop_event.is_set():
            break  # Exit the loop if the animation has been stopped
        
        # MD5
        if hash_type == "MD5":
            if hashlib.md5(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # SHA1
        elif hash_type == "SHA1":
            if hashlib.sha1(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # SHA256
        elif hash_type == "SHA256":
            if hashlib.sha256(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # SHA512
        elif hash_type == "SHA512":
            if hashlib.sha512(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # SHA3-256
        elif hash_type == "SHA3-256":
            if hashlib.sha3_256(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # SHA3-512
        elif hash_type == "SHA3-512":
            if hashlib.sha3_512(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # NTLM
        elif hash_type == "NTLM":
            if hashlib.new('md4', word.encode('utf-16le')).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # LM
        elif hash_type == "LM":
            # LM hashes are not directly supported, but you could use a specialized library
            pass
        
        # bcrypt
        elif hash_type == "bcrypt":
            if bcrypt.checkpw(word.encode(), hash_value.encode()):
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # scrypt
        elif hash_type == "scrypt":
            # scrypt implementation requires a library such as `scrypt`
            pass
        
        # PBKDF2
        elif hash_type == "PBKDF2":
            if pbkdf2_sha1.hash(word) == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # Argon2
        elif hash_type == "Argon2":
            if argon2.verify(word, hash_value):
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        
        # Django SHA1
        elif hash_type == "Django SHA1":
            # Django SHA1 hash verification
            pass
        
        # Django SHA256
        elif hash_type == "Django SHA256":
            # Django SHA256 hash verification
            pass
        
        # Django SHA512
        elif hash_type == "Django SHA512":
            # Django SHA512 hash verification
            pass
        
        # Drupal SHA512
        elif hash_type == "Drupal SHA512":
            # Drupal SHA512 hash verification
            pass
    
    stop_event.set()  # Stop the animation if the wordlist is exhausted
    return None

def main():
    landing_page()

    hash_value = input("Enter the hash to crack: ").strip()
    complexity = int(input("Enter the complexity level (1-5 for basic, 6-10 for intermediate, 11+ for advanced): ").strip())
    
    hash_type = identify_hash(hash_value)
    if hash_type == "Unknown":
        print("Hash type could not be identified.")
        return
    
    print(f"Hash type identified: {hash_type}")
    
    wordlist = select_wordlist(complexity)
    if not wordlist:
        print("No wordlist available.")
        return

    stop_event = threading.Event()
    animation_thread = threading.Thread(target=animate_cracking, args=(stop_event,))
    animation_thread.start()

    cracked_password = crack_hash(hash_value, hash_type, wordlist, stop_event)
    
    if cracked_password:
        print(f"Hash cracked! The password is: {cracked_password}")
    else:
        print("Failed to crack the hash.")
    
    stop_event.set()
    animation_thread.join()

if __name__ == "__main__":
    main()
