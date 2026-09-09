# PassAudit-CLI

A lightweight credential evaluation tool implementing Information Theory (Shannon Entropy) and remote breach verification using SHA-1 prefix-based k-Anonymity.

---

### Architectural Overview

[Plaintext Credential]
       |
       +---> [Shannon Entropy Engine] ---------> Entropy Score (Bits)
       |
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

---

### Key Technical Considerations

1. Zero Exposure Perimeter: The plaintext credential never traverses disk storage, stdout buffers, or network interfaces.
2. k-Anonymity Model: The API endpoint receives only the first 5 hexadecimal characters of the SHA-1 digest, returning candidate hashes. The remaining 35 characters are evaluated in memory locally.
3. Entropy Metric: Uses character frequency distribution rather than naive regex checks to quantify randomness against brute-force complexity.

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
