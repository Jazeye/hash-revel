import hashlib
import requests
import time
import sys
import threading

# Landing screen
def landing_page():
    print("=====================================")
    print("   Hash Identifier and Cracker  ")
    print("   Developed by: Jassel")
    print("   Version: 0.1")
    print("=====================================")
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
        
        if hash_type == "MD5":
            if hashlib.md5(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        elif hash_type == "SHA1":
            if hashlib.sha1(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        elif hash_type == "SHA256":
            if hashlib.sha256(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        elif hash_type == "SHA512":
            if hashlib.sha512(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        elif hash_type == "SHA3-256":
            if hashlib.sha3_256(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        elif hash_type == "SHA3-512":
            if hashlib.sha3_512(word.encode()).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word
        elif hash_type == "NTLM":
            if hashlib.new('md4', word.encode('utf-16le')).hexdigest() == hash_value:
                stop_event.set()  # Stop the animation once the hash is cracked
                return word

    stop_event.set()  # Ensure the animation stops if the hash wasn't cracked
    return None

# Display complexity levels
def display_complexity_levels():
    print("Complexity Levels:")
    print("1-5: Basic wordlist (shorter lists)")
    print("6-10: Intermediate wordlists (medium-length lists)")
    print("11+: Advanced wordlists (longer and more comprehensive lists)")
    print("")

# Main script logic
def main():
    landing_page()
    display_complexity_levels()

    hash_value = input("Enter the hash value: ")
    complexity = int(input("Enter the complexity level (1-10): "))

    hash_type = identify_hash(hash_value)
    print(f"Hash Type: {hash_type}")

    if hash_type == "Unknown":
        print("Unknown hash type. Exiting.")
        return

    wordlist = select_wordlist(complexity)
    if not wordlist:
        print("Failed to load wordlist. Exiting.")
        return

    while True:
        crack_prompt = input("Do you want to attempt to crack the hash? (yes/no): ").strip().lower()
        if crack_prompt in ["yes", "y"]:
            stop_event = threading.Event()
            animation_thread = threading.Thread(target=animate_cracking, args=(stop_event,))
            animation_thread.start()

            cracked_password = crack_hash(hash_value, hash_type, wordlist, stop_event)
            animation_thread.join()  # Ensure animation stops before printing the result

            if cracked_password:
                print(f"\nSuccess! The password is: {cracked_password}")
            else:
                print("\nFailed to crack the hash.")
            break
        elif crack_prompt in ["no", "n"]:
            print("Hash cracking aborted.")
            break
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

if __name__ == "__main__":
    main()
