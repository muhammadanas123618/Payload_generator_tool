# 🔐 Payload Generator Tool

A modular command-line Python tool to generate **XSS**, **SQL Injection**, and **Command Injection** payloads — perfect for use in penetration testing, bug bounty hunting, and web application security assessments.

---

## 📌 Features

- ✅ XSS payload generation with support for:
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
- ✅ SQLi payload generation
- ✅ CMDi (Command Injection) payload generation
- 🔐 Optional encoding (Base64, URL)
- 🌐 OWASP ZAP API integration (optional)
- 🧑‍💻 Simple GUI interface (optional via Tkinter)

---

## 🖥️ Installation

```bash
git clone https://github.com/muhammadanas123618/payload_generator_tool.git
cd payload_generator_tool
pip install -r requirements.txt

---

⚙️ Usage

python main.py [OPTIONS]

🔧 Options
Option	Description	Example
--xss	Generate XSS payloads	--xss
--sqli	Generate SQLi payloads	--sqli
--cmdi	Generate CMDi payloads	--cmdi
--encode	Encoding: base64 or url	--encode=base64
--count	Number of payloads to display	--count=5
--gui	Launch the GUI version (Tkinter)	--gui
--zap-scan	Run an OWASP ZAP scan (optional)	--zap-scan http://target.com
🧪 Examples

Generate 5 Base64-encoded XSS payloads:

python main.py --xss --encode=base64 --count=5

Generate 3 SQL injection payloads:

python main.py --sqli --count=3

Launch GUI:

python main.py --gui

Run ZAP Scan:

python main.py --zap-scan http://example.com

🛠️ Dependencies

Install with:

pip install -r requirements.txt

Includes:

    Flask (for web interface, optional)

    tkinter (for GUI)

    requests (for ZAP API)

    argparse, base64, urllib.parse

🔒 Security Disclaimer

This tool is intended only for authorized penetration testing, ethical hacking, or educational purposes. Misuse of this tool for unauthorized access is illegal and unethical.
👨‍💻 Author

Muhammad Anas
