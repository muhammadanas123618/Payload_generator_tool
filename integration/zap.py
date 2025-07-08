import requests

def send_payload_to_zap(target_url, payload):
    zap_api = "http://localhost:8080"  # default ZAP API location
    try:
        print(f"[ZAP] Sending payload: {payload}")
        requests.get(f"{target_url}?input={payload}")
    except Exception as e:
        print(f"[ZAP] Failed to send payload: {e}")
