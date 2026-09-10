import streamlit as st
import math
import hashlib
import requests

def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    entropy = 0.0
    length = len(password)
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy * length, 2)

def check_hibp_breach(password: str) -> int:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "PassAudit-Web-Tool"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code != 200:
            return -1
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return -1

st.set_page_config(page_title="PassAudit Web", page_icon="🛡️", layout="centered")

st.title(" PassAudit Web")
st.markdown("### Zero-Knowledge Credential Security & Breach Auditor")
st.caption("Evaluate real-time Shannon Entropy and remote breach exposure via k-Anonymity.")

password_input = st.text_input("Enter password to evaluate:", type="password", help="Evaluated locally in volatile memory.")

if st.button("Audit Password", type="primary"):
    if not password_input:
        st.warning("Please enter a password first.")
    else:
        entropy = calculate_entropy(password_input)
        breach_count = check_hibp_breach(password_input)
        
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric(label="Entropy Score", value=f"{entropy} bits")
            if entropy < 40:
                st.error("Verdict: Very Weak / Predictable")
            elif entropy < 60:
                st.warning("Verdict: Moderate Randomness")
            else:
                st.success("Verdict: Robust / High Randomness")
                
        with col2:
            if breach_count > 0:
                st.metric(label="Breach Status", value="COMPROMISED", delta=f"-{breach_count} leaks", delta_color="inverse")
                st.error(f"Found in {breach_count:,} public data breaches!")
            elif breach_count == 0:
                st.metric(label="Breach Status", value="CLEAN", delta="Safe")
                st.success("Zero occurrences found in HIBP database.")
            else:
                st.warning("Breach service temporarily unreachable.")
