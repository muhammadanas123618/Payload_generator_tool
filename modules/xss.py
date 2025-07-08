import json
import os
from utils.encoder import encode_payload
from utils.obfuscator import obfuscate_payload

def generate_xss_payloads(encoding=None, obfuscate=False, bypass=False):
    payloads = []
    if bypass:
        with open(os.path.join("payloads", "waf_bypass.json")) as f:
            raw = json.load(f)["xss"]
        for p in raw:
            if obfuscate:
                p = obfuscate_payload(p)
            if encoding:
                p = encode_payload(p, encoding)
            payloads.append({ "type": "waf-bypass", "payload": p })
        return payloads

    with open(os.path.join("payloads", "xss.json")) as f:
        raw_payloads = json.load(f)

    for category, items in raw_payloads.items():
        for p in items:
            if obfuscate:
                p = obfuscate_payload(p)
            if encoding:
                p = encode_payload(p, encoding)
            payloads.append({ "type": category, "payload": p })
    return payloads
