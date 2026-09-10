# PassAudit-CLI
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat&logo=python&logoColor=white)  ![Security](https://img.shields.io/badge/Audit-k--Anonymity-red?style=flat&logo=security)  ![License](https://img.shields.io/badge/License-MIT-green?style=flat) [![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://thecyberyash-passaudit.streamlit.app)

🔗 **Live Web Demo:** [thecyberyash-passaudit.streamlit.app](https://thecyberyash-passaudit.streamlit.app)

A lightweight credential evaluation tool implementing Information Theory (Shannon Entropy) and remote breach verification using SHA-1 prefix-based k-Anonymity.

---

### Architectural Overview

```
[Plaintext Credential]

       |
       +---> [Shannon Entropy Engine] ---------> Entropy Score (Bits)
       
       +---> [SHA-1 Digest Engine]
                    |
                    +---> [5-Char Prefix] -----> HIBP API (k-Anonymity)
                    |                                  |
                    +---> [35-Char Suffix] <----+ (Candidate Set)
                                 |
                          [Local Verification]
                                 |
                                 v
                        [Compromise Status]
```
---

### Key Technical Considerations

1. Zero Exposure Perimeter: The plaintext credential never traverses disk storage, stdout buffers, or network interfaces.
2. k-Anonymity Model: The API endpoint receives only the first 5 hexadecimal characters of the SHA-1 digest, returning candidate hashes. The remaining 35 characters are evaluated in memory locally.
3. Entropy Metric: Uses character frequency distribution rather than naive regex checks to quantify randomness against brute-force complexity.
---

### Mathematical Foundation
Entropy is calculated using Claude Shannon’s Information Entropy formula:
<img width="385" height="125" alt="image" src="https://github.com/user-attachments/assets/9d15ebc4-beeb-4b49-8ba3-f68887ebb01e" />
Where:
- $P(x_i)$ is the probability of character $x_i$ occurring within the credential string.
- The resulting value represents the bits of entropy per character, quantifying the credential's resistance against offline brute-force attacks.

---
### Example Output

```bash
$ python main.py
Enter password to evaluate: [HIDDEN]

[*] Shannon Entropy: 68.42 bits (Strong)
[*] HIBP Status: Compromised (Appeared 1,420 times in breach corpora)
[!] Verdict: High algorithmic strength, but compromised in known public leaks.
```
---

### Evaluation Matrix

| Credential Type | Sample Pattern | Shannon Entropy | HIBP Status | Final Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Predictable** | `Password123!` | < 35 bits | Compromised | **Critical Failure** |
| **Randomized Short** | `aB8#kL2@` | 40–55 bits | Uncompromised | **Moderate Risk** |
| **High-Entropy Secret** | `k9#vL@8$qP0!zW` | > 65 bits | Clean | **Robust** |
---
### Threat Model & Limitations

- **Shannon vs. Dictionary Space:** Shannon Entropy assumes a uniform symbol space. A passphrase like `CorrectHorseBatteryStaple` exhibits lower per-character entropy than random noise (`x9#K2@`), yet resists dictionary attacks significantly better due to key length.
- **k-Anonymity Privacy Guarantee:** The tool truncates the SHA-1 digest to a 5-character prefix ($16^5 = 1,048,576$ candidate buckets). An observer monitoring network traffic cannot reconstruct the original 40-character hash or derive the candidate password.
- **Volatile Execution Scope:** Plaintext credentials exist only in transient memory during evaluation, captured via secure masking (`getpass`), with zero persistence to disk or unmasked stdout streams.

---
### Installation & Run

1. Install dependencies:
pip install requests

2. Run the tool:
python main.py
---
### Dependencies
- requests (HTTP transport for k-Anonymity queries)
- Standard Library: hashlib, math, getpass, sys
---
### License

This project is open source and available under the [MIT License](LICENSE).
