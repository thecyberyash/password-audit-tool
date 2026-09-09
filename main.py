import hashlib
import requests
import math
import getpass

def calculate_entropy(password):
    """Calculates the Shannon Entropy of the password in bits."""
    if not password:
        return 0.0
    
    # Har character ki frequency count karna
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
        
    length = len(password)
    entropy_per_char = 0.0
    
    # Shannon Entropy formula
    for count in char_counts.values():
        probability = count / length
        entropy_per_char -= probability * math.log2(probability)
        
    total_entropy = entropy_per_char * length
    return round(total_entropy, 2)

def check_breach(password):
    """Checks HIBP database using SHA-1 k-Anonymity model."""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return None, "API connection failed"
            
        hashes = response.text.splitlines()
        for line in hashes:
            h_suffix, count = line.split(':')
            if h_suffix == suffix:
                return int(count), "PWNED"
        return 0, "SAFE"
    except Exception as e:
        return None, str(e)

def main():
    print("=" * 60)
    print("      PASSWORD INTELLIGENCE & BREACH AUDIT TOOL")
    print("=" * 60)
    
    # Password safely input lena (screen par text hide rahega)
    password = getpass.getpass("Enter password to audit (input will be hidden): ")
    
    if not password:
        print("Error: Empty password provided.")
        return

    print("\nRunning Security Audit...")
    
    # 1. Entropy Evaluation
    entropy = calculate_entropy(password)
    print(f"\n[+] Shannon Entropy Score : {entropy} bits")
    
    if entropy < 40:
        print("    Verdict               : WEAK (Predictable pattern)")
    elif entropy < 60:
        print("    Verdict               : MODERATE (Can be strengthened)")
    else:
        print("    Verdict               : STRONG (High mathematical randomness)")
        
    # 2. Threat Intelligence Check (HIBP)
    count, status = check_breach(password)
    
    if status == "PWNED":
        print(f"\n[!] BREACH ALERT          : COMPROMISED")
        print(f"    Occurrences           : Found in {count:,} public data leaks!")
        print("    Action Required       : NEVER use this password. Change immediately.")
    elif status == "SAFE":
        print(f"\n[✓] BREACH STATUS         : SAFE")
        print("    Occurrences           : 0 breaches found across 80+ crore records.")
    else:
        print(f"\n[-] BREACH STATUS         : Check Skipped ({status})")
        
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()