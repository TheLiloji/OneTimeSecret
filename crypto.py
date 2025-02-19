import os
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from typing import Tuple, Optional

class SecretCrypto:
    def __init__(self, master_key: bytes):
        self.master_key = master_key
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Dérive une clé unique pour chaque secret"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self.master_key)
    
    def encrypt_secret(self, secret: str) -> Tuple[bytes, bytes, bytes]:
        """
        Chiffre un secret avec AES-GCM
        Retourne: (ciphertext, salt, nonce)
        """
        # Génère un salt unique pour la dérivation de clé
        salt = os.urandom(16)
        key = self._derive_key(salt)
        
        # Chiffrement AES-GCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, secret.encode(), None)
        
        return ciphertext, salt, nonce
    
    def decrypt_secret(self, ciphertext: bytes, salt: bytes, nonce: bytes) -> Optional[str]:
        """
        Déchiffre un secret
        Retourne None si le déchiffrement échoue
        """
        try:
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except (InvalidTag, UnicodeDecodeError):
            return None

def generate_token() -> str:
    """Génère un token aléatoire sécurisé pour l'URL"""
    return urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
