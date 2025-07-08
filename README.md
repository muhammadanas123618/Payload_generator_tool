# 🔐 Payload Generator Tool

A modular command-line Python tool to generate **XSS**, **SQL Injection**, and **Command Injection** payloads — perfect for penetration testing, bug bounty hunting, and web application security assessments.

---

## 📌 Features

- ✅ XSS payload generation with support for:
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
- ✅ SQLi payload generation (error-based, union-based, blind)
- ✅ CMDi (Command Injection) payload generation (Linux & Windows)
- ✴️ Obfuscation options
- 🔐 Optional encoding:
  - Base64
  - URL
  - Hex
  - Unicode
- 🌐 **OWASP ZAP API** integration (optional)
- 🧑‍💻 **Simple GUI interface** (optional via Tkinter)

---

## 🖥️ Installation

```bash
git clone https://github.com/muhammadanas123618/payload_generator_tool.git
cd payload_generator_tool
pip install -r requirements.txt
```

---

## ⚙️ Usage

```bash
python main.py [OPTIONS]
```

---

### 🔧 Options

| Option         | Description                         | Example                          |
|----------------|-------------------------------------|----------------------------------|
| `--xss`        | Generate XSS payloads               | `--xss`                          |
| `--sqli`       | Generate SQLi payloads              | `--sqli`                         |
| `--cmdi`       | Generate CMDi payloads              | `--cmdi`                         |
| `--encode`     | Encode output (`base64`, `url`, etc.) | `--encode=base64`               |
| `--obfuscate`  | Obfuscate payloads                  | `--obfuscate`                    |
| `--output`     | Output format (`cli`, `json`, `clipboard`) | `--output=cli`             |
| `--gui`        | Launch the GUI version (Tkinter)    | `--gui`                          |
| `--zap`   | Run a ZAP API scan on a URL         | `--zap http://target.com`  |

---

### 🧪 Examples

✅ Generate Base64-encoded XSS payloads:
```bash
python main.py --xss --encode=base64
```

✅ Generate SQL Injection payloads:
```bash
python main.py --sqli
```

✅ Launch the GUI:
```bash
python main.py --gui
```

✅ Run ZAP scan:
```bash
python main.py --zap http://example.com
```

---

## 🛠️ Dependencies

Install with:

```bash
pip install -r requirements.txt
```

### Required Libraries:

- `tkinter` – for GUI (Tkinter is built-in with most Python installs)
- `requests` – for ZAP API integration
- `pyperclip` – for clipboard functionality
- Standard modules: `argparse`, `base64`, `json`, `urllib.parse`, etc.

---

## 🔒 Security Disclaimer

> This tool is intended **only** for authorized penetration testing, ethical hacking, or educational purposes.  
> **Misuse** of this tool to gain unauthorized access or disrupt services is illegal and unethical.

---

## 👨‍💻 Author

**Muhammad Anas**  
[GitHub: @muhammadanas123618](https://github.com/muhammadanas123618)
