import argparse
import json
import pyperclip

from modules.xss import generate_xss_payloads
from modules.sqli import generate_sqli_payloads
from modules.cmdi import generate_cmdi_payloads
from utils.encoder import encode_payload
from utils.obfuscator import obfuscate_payload
from gui.tk_gui import run_gui
from integration.zap import send_payload_to_zap


def generate_payloads(module, encoding=None, obfuscate=False, bypass=False):
    if module == "xss":
        return generate_xss_payloads(encoding, obfuscate, bypass)
    elif module == "sqli":
        return generate_sqli_payloads(encoding, obfuscate, bypass)
    elif module == "cmdi":
        return generate_cmdi_payloads(encoding, obfuscate, bypass)
    return []


def main():
    parser = argparse.ArgumentParser(description="Payload Generator Tool")

    parser.add_argument("--xss", action="store_true", help="Generate XSS payloads")
    parser.add_argument("--sqli", action="store_true", help="Generate SQLi payloads")
    parser.add_argument("--cmdi", action="store_true", help="Generate command injection payloads")
    
    parser.add_argument("--encode", choices=["base64", "url", "hex", "unicode"], help="Encode the payloads")
    parser.add_argument("--obfuscate", action="store_true", help="Obfuscate the payloads")
    parser.add_argument("--bypass", action="store_true", help="Use WAF bypass payloads")
    parser.add_argument("--output", choices=["cli", "json", "clipboard"], default="cli", help="Output format")

    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("--zap", metavar="URL", help="Send payloads to OWASP ZAP for testing")

    args = parser.parse_args()

    if args.gui:
        run_gui()
        return

    module = None
    if args.xss:
        module = "xss"
    elif args.sqli:
        module = "sqli"
    elif args.cmdi:
        module = "cmdi"

    if module:
        result = generate_payloads(module, args.encode, args.obfuscate, args.bypass)

        if args.zap:
            for payload in result:
                send_payload_to_zap(args.zap, payload['payload'])

        if args.output == "cli":
            for item in result:
                print(f"[{item['type']}] {item['payload']}")
        elif args.output == "json":
            print(json.dumps(result, indent=2))
        elif args.output == "clipboard":
            pyperclip.copy(json.dumps(result))
            print("Payloads copied to clipboard.")
    else:
        print("Please specify a module: --xss, --sqli, or --cmdi")


if __name__ == "__main__":
    main()
