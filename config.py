import os
from datetime import timedelta

class Config:
    # Sécurité générale
    SECRET_KEY = os.urandom(32)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Limites de l'application
    MAX_SECRET_SIZE = 10 * 1024  # 10 KB
    MAX_SECRETS_PER_IP = 10
    RATE_LIMIT_REQUESTS = 10
    RATE_LIMIT_WINDOW = 60  # secondes
    
    # Durée de vie des secrets
    SECRET_LIFETIME = timedelta(hours=24)
    
    # En-têtes de sécurité
    SECURITY_HEADERS = {
        'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline';",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'no-referrer',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
    
    # Configuration du chiffrement
    ENCRYPTION_KEY_LENGTH = 32
    KEY_DERIVATION_ITERATIONS = 100000
    
    # Logging
    LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'secret_service.log'
    
    @staticmethod
    def init_app(app):
        """Initialize application configuration"""
        pass
