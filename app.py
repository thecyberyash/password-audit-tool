import streamlit as st
import hashlib
import requests
import math
import secrets
import string

st.set_page_config(page_title="PassAudit Web", page_icon="🛡️", layout="centered")

st.title("PassAudit Web 🛡️")
st.subheader("Zero-Knowledge Credential Security & Breach Auditor")
st.caption("Evaluate real-time Shannon Entropy and remote breach exposure via k-Anonymity.")

# --- Logic Functions ---
def calculate_entropy(pwd):
    if not pwd:
        return 0.0
    char_counts = {}
    for char in pwd:
        char_counts[char] = char_counts.get(char, 0) + 1
    entropy = 0.0
    length = len(pwd)
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy * length, 2)

def check_hibp_breach(pwd):
    sha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "PassAudit-Web"}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code != 200:
            return None
        for line in res.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return None

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(chars) for _ in range(length))

# --- Audit Section ---
pwd_input = st.text_input("Enter password to evaluate:", type="password")

if st.button("Audit Password", type="primary"):
    if not pwd_input:
        st.warning("Please enter a password first.")
    else:
        entropy = calculate_entropy(pwd_input)
        breach_count = check_hibp_breach(pwd_input)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Entropy Score", f"{entropy} bits")
            if entropy < 40:
                st.error("Verdict: Very Weak / Predictable")
            elif entropy < 60:
                st.warning("Verdict: Moderate")
            else:
                st.success("Verdict: Cryptographically Strong")

        with col2:
            if breach_count is None:
                st.info("Breach Check: API Unavailable")
            elif breach_count > 0:
                st.metric("Breach Status", "EXPOSED", delta=f"-{breach_count} leaks", delta_color="inverse")
                st.error(f"Pwned in {breach_count:,} public data leaks!")
            else:
                st.metric("Breach Status", "CLEAN", delta="Safe")
                st.success("Zero occurrences found in HIBP database.")

st.divider()

# --- Generator Section ---
st.markdown("### 🔑 Need a Strong Password?")
gen_len = st.slider("Password Length", min_value=12, max_value=32, value=16)

if st.button("Generate Secure Password"):
    new_pwd = generate_strong_password(gen_len)
    st.code(new_pwd, language="")
    gen_entropy = calculate_entropy(new_pwd)
    st.caption(f"Calculated Entropy: **{gen_entropy} bits** (Cryptographically Random)")
