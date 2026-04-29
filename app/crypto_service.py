from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()


def sign_data(private_key_pem: str, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
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


def verify_signature(public_key_pem: str, data: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    

DEMO_ENCRYPTION_KEY = b"Y3s5QpXAmHk0mXhprKQBOkYz6Hz1FfOaCUsx4eABdY0="


def encrypt_data(plain_text: str) -> str:
    fernet = Fernet(DEMO_ENCRYPTION_KEY)
    encrypted = fernet.encrypt(plain_text.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_data(encrypted_text: str) -> str:
    fernet = Fernet(DEMO_ENCRYPTION_KEY)
    decrypted = fernet.decrypt(encrypted_text.encode("utf-8"))
    return decrypted.decode("utf-8")