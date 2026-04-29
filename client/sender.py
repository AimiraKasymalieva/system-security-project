import requests
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

#from client.config import PRIVATE_KEY, TOKEN

PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0C07QbBAg5BQT\nZedpOxtiHdK9UM9Kl0q1n/KLgKqjltJCePZMbzh14Eut/J/jBPRPOvJH8i80vnic\neNH4MM4wwLuEsqUx4oNGzCyacnZgsriPCgM4gYgXeez2Ja1BBApS6pQJOKLo2vrb\nEN+cZr3TU8NxcHvDm/xxpAR9fnxncRK/8Dbc7JAtNjk4s+Ezyurdutnxq5tk/Gjs\nApSteJ9/r9LuR4SsviQsljxNaGn0SpZkoYQrePXLTWoRPVW/eF92pfl1/cOCBPuz\nRgx+SGblahTTlShUkl2pejaaz19CPh+QITPgRg3q1hTEeHouO/fnDqxEux0paeTw\nKVNnbM5vAgMBAAECggEAJCyHc9HadblNnU4irh5tlIuYbWgglgSKwq41zbiW0FJ7\nwVZLajUIe4qKuhThTPwQWCDoT/NFb8v7MLkHut2Xd+0pX/KCxWCU7rMUHR31Ud1m\nvnqNBhvka48YQKZ2RnNY3ar6/lVOSgnBUCV2QBbWefDA+nhWrYkYMf751fsFZMTY\njYWknHTSYpv0mRXcMEEzhPd2bBhlwkAycJ50m93tJMSAXOi1fL1k1c6QIeJsTKSy\nfmRM7OGfNVPOXiclLA6rz5N+yduKTqMC8HhwgLLiWruAgmDPcmi/TMkZdqJyE7XW\nJhRQGUE8e/IGvcfjTDl5FLgSOeOs8FgZn9F/TUdE5QKBgQD32pJgubDgkZAawKKC\ntDCHvcAO9hMX1SrOpRnFObyQ+QKE8Z47FFbxsOVWceNRfb/+5IKVggFj/N4fQ8Ft\n/0xkdOrVaGlcSVeUGQGH9SnhsaHiQ4rMkhC3jQ1cnmOyTTyftQ7g9nAa/46Kq86s\n3HctGcZPm0GF7ciR4+9g3sAjywKBgQC59jCLUFvf/YMom2xwX3pGE1pBHC8JBGcE\n2dBRqEaAbBFq7YZBX1f+A/rlA0b+rpKeXJhNIsrxqkrJUi8OInQD1BrYg8eNKJy7\nW7dK/rIcnOCkEPZsnI/d0iZUy50crSaO6kGhzpTfXeX/CuVexWdAcMaM0fRociJw\nJN3R7zCTbQKBgHFmZqysqRnGX9lto60LhlzE23e87LVtyZ0seuL67KSj2Zw79Dpx\nrun8FqH7j5b8YvjbUkfXaI1356UEWh7avPgFamBj2jjoMZLH8iRjblsd68RbRMke\nV1mzxpZGvbSZlBA6Rel1t4sSvAQEYZZDdJ+E+G/5x/vf9HGTiTWYFO8LAoGAK0Wg\nUiqm1l5VcNOJzjRJbZj/PXtjboO5vSU6FmZD0YpUGz+eKAQZo6Ald7jlgkn5ECSX\nxAs+kjGAKYyYKn/V4zYt8QfpHW2/2tEiu668n2/ZzhOsY+WijIlkJgMjUhLwj/zu\nvMonVjqxVEGi0gS5XANiEE6iwtMcNGA/xaQU95kCgYBSU7I7yJf/zSBFBPhJ0nRS\n1EHZ/G0l403FGXSfj7Zg7OQT6Dxir0UaNDqWRgNr8FczRtsBNZfZHOfZEm/h4VSz\n6FSaoA6uWzguZfsi6azyBsM2okF5qxLIyzZCd8FXEgLNfIj0S88Cus+3S/U0NFtP\noKnGHpgz+RGinKIIz36fsw==\n-----END PRIVATE KEY-----\n"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhaW0iLCJ1c2VyX2lkIjoyLCJleHAiOjE3NzcxMjcxODl9.CwWDGqHqxxOchVhomdncaTSy8rEAU6dqI9VNE_ymqEM"
URL = "http://127.0.0.1:8000/data/send"


def sign_data(private_key_pem: str, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY.encode("utf-8"),
        password=None
    )

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


original_payload = {
    "device_id": "sensor_01",
    "temperature": 25,
    "humidity": 60,
    "timestamp": "2026-04-22T23:20:00"
}

original_json = json.dumps(
    original_payload,
    sort_keys=True,
    separators=(",", ":")
)
original_bytes = original_json.encode("utf-8")

signature = sign_data(PRIVATE_KEY, original_bytes)
signature_b64 = base64.b64encode(signature).decode("utf-8")

headers = {
    "Authorization": f"Bearer {TOKEN}"
}

print("=== VALID REQUEST ===")
response_valid = requests.post(
    URL,
    json={
        "payload": original_payload,
        "signature": signature_b64
    },
    headers=headers
)

print("Status:", response_valid.status_code)
print("Response:", response_valid.text)
print()

tampered_payload = {
    "device_id": "sensor_01",
    "temperature": 999,
    "humidity": 60,
    "timestamp": "2026-04-22T23:20:00"
}

print("=== TAMPERED REQUEST ===")
response_tampered = requests.post(
    URL,
    json={
        "payload": tampered_payload,
        "signature": signature_b64
    },
    headers=headers
)

print("Status:", response_tampered.status_code)
print("Response:", response_tampered.text)