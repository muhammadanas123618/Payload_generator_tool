import base64
import urllib.parse

def encode_payload(payload, encoding):
    if encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "hex":
        return payload.encode().hex()
    elif encoding == "unicode":
        return ''.join(['\\u{:04x}'.format(ord(c)) for c in payload])
    return payload
