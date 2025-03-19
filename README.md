![PathSeeker Banner](https://img.shields.io/badge/PathSeeker-blue?style=for-the-badge)  
**A lightweight, multi-threaded Path Traversal Vulnerability Scanner.**

PathSeeker is a Python-based tool designed to identify path traversal vulnerabilities in web applications. It uses a combination of multi-threading, random user agents, and a robust wordlist to efficiently test endpoints for potential security weaknesses. Developed by Praveen Kavinda, PathSeeker is intended for security researchers and penetration testers with explicit permission to test target systems.

> **WARNING**: PathSeeker should only be used on systems you own or have explicit permission to test. Unauthorized use may violate laws and ethical guidelines.

---

## Features

- **Multi-Threaded Scanning**: Speeds up testing by processing multiple payloads concurrently.
- **Random User Agents**: Rotates user agents and headers to evade detection.
- **Customizable Wordlist**: Use the default payload list or provide your own.
- **Smart URL Handling**: Correctly modifies specified parameters without breaking query strings.
- **Vulnerability Detection**: Identifies potential leaks with keyword-based content analysis.
- **Interactive Workflow**: Prompts users to continue, skip, or exit upon finding vulnerabilities.
- **Output Saving**: Saves results to a file for later review.

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/praveenkavi5/PathSeeker.git
   cd PathSeeker
   ```

2. **Install Dependencies**:
   PathSeeker requires Python 3.6+ and the `requests` library. Install it using:
   ```bash
   pip install requests
   ```

3. **Run the Tool**:
   ```bash
   python pathseeker.py
   ```

---

## Usage

### Basic Command
Run PathSeeker with default settings:
```bash
python pathseeker.py
```

### Input Prompts
- **Base URL**: Enter the target URL (e.g., `https://example.com/page?url=test&w=256`).
- **Parameter**: Specify the parameter to test (e.g., `url`).
- **Custom Wordlist**: (Optional) Provide a file path to your payload list.
- **Max Threads**: (Optional) Set the number of concurrent threads (default: 10).

### Example
```plaintext
==========================================================
                        PathSeeker                    
----------------------------------------------------------
   Developed by Praveen Kavinda
   Website: https://prav33n.me
----------------------------------------------------------
~ WARNING: Use only on systems you own or have explicit permission to test! ~
==========================================================
Enter the base URL (e.g., https://topads.lk/_next/image?url=TEST&w=256&q=75): https://topads.lk/_next/image?url=TEST&w=256&q=75
Enter the parameter to test (e.g., url): url
Enter custom wordlist file path (leave blank to use default): 
Enter max threads (default 10): 5

[*] Starting PathSeeker Test...
[*] Target: https://topads.lk/_next/image?url=TEST&w=256&q=75
[*] Parameter: url
[*] Total payloads: 60
[*] Max threads: 5
-
[>] https://prav33n.me/_next/image?url=TEST&a=test2&b=test3 | Status: 400 | Length: 26 | "url" parameter is invalid
...
[*] No clear vulnerabilities detected by PathSeeker. Check responses manually for subtle leaks.
```

### Custom Wordlist
Create a text file (e.g., `payloads.txt`) with one payload per line:
```
../../etc/passwd
../secret.txt
%2e%2e%2fconfig.php
```
Then provide the path when prompted.

---

## Requirements

- **Python**: 3.6 or higher
- **Dependencies**:
  - `requests` (install via `pip install requests`)

---

## How It Works

1. **Input Parsing**: PathSeeker takes a base URL and a target parameter, preserving other query parameters.
2. **Payload Testing**: It tests each payload (and its double-encoded version) using multi-threading.
3. **Response Analysis**: Checks for HTTP 200 responses and sensitive keywords (e.g., `root`, `passwd`).
4. **User Interaction**: Prompts for next steps if vulnerabilities are found.
5. **Output**: Optionally saves results to a file.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m "Add your feature"`).
4. Push to your branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

Please ensure your code follows PEP 8 guidelines and includes comments where necessary.


---

## Author

- **Praveen Kavinda**
- **Website**: [https://prav33n.me](https://prav33n.me)
- **GitHub**: [prav33n](https://github.com/praveenkavi5)

---

## Disclaimer

PathSeeker is provided for educational and ethical security testing purposes only. The author is not responsible for any misuse or damage caused by this tool. Use responsibly and legally.

---

## Future Improvements

- Add proxy support for anonymity.
- Implement rate limiting to avoid detection.
- Enhance payload generation with OS-specific patterns.
- Improve false positive filtering with advanced content analysis.

Feel free to suggest new features via [Issues](https://github.com/praveenkavi5/PathSeeker/issues)!
```
