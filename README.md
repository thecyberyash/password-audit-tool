# PassAudit-CLI

A lightweight credential evaluation tool implementing Information Theory (Shannon Entropy) and remote breach verification using SHA-1 prefix-based k-Anonymity.

---

### Key Technical Considerations

1. **Zero Exposure Perimeter:** The plaintext credential never traverses disk storage, stdout buffers, or network interfaces.
2. **k-Anonymity Model:** The API endpoint receives only the first 5 hexadecimal characters of the SHA-1 digest, returning candidate hashes. The remaining 35 characters are evaluated in memory locally.
3. **Entropy Metric:** Uses character frequency distribution rather than naive regex checks to quantify randomness against brute-force complexity.

---

### Installation & Run

1. Dependencies install karein:
```bash
pip install requests