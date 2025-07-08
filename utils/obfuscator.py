def obfuscate_payload(payload):
    return payload.replace("<", "</**/").replace(" ", "/**/").replace("script", "scr/**/ipt")
