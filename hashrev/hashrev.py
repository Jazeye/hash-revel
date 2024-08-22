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
    elif len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value) and len(hash_value) == 64:
        hash_type = "NTLM"
    elif len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value) and len(hash_value) == 96:
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
    
    return hash_type

# Define a function to select the best wordlist based on the hash type and complexity
def select_wordlist(hash_type, complexity):
    if hash_type in ["MD5", "SHA1", "NTLM"]:
        if complexity <= 5:
            wordlist_url = "https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt"
        elif complexity <= 10:
            wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
        else:
            wordlist_url = "https://raw.githubusercontent.com/hashkiller/hashkiller.github.io/master/wordlists/100-million-passwords.txt"
    elif hash_type in ["SHA256", "SHA512", "SHA3-256", "SHA3-512"]:
        if complexity <= 5:
            wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
        else:
            wordlist_url = "https://raw.githubusercontent.com/openwall/john/master/src/wordlists/password.lst"
    else:
        wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"

    return wordlist_url

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
def crack_hash(hash_value, hash_type, wordlist_url, stop_event):
    # Download the wordlist
    response = requests.get(wordlist_url)
    wordlist = response.text.splitlines()

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
    print("1-5: Basic wordlists (shorter lists)")
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

    wordlist_url = select_wordlist(hash_type, complexity)

    crack_choice = input("Do you want to attempt to crack the hash? (y/n): ")

    if crack_choice.lower() == 'y':
        stop_event = threading.Event()
        animation_thread = threading.Thread(target=animate_cracking, args=(stop_event,))
        animation_thread.start()

        cracked_password = crack_hash(hash_value, hash_type, wordlist_url, stop_event)
        animation_thread.join()  # Ensure animation stops before printing the result

        if cracked_password:
            print(f"\nHash cracked successfully! Password: {cracked_password}")
        else:
            print("\nFailed to crack the hash.")
    else:
        print("Hash cracking skipped.")

if __name__ == "__main__":
    main()
