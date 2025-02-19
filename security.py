from flask import request, abort
from functools import wraps
import time
import structlog
from typing import Dict, Set
from collections import defaultdict

logger = structlog.get_logger()

class RateLimiter:
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, list] = defaultdict(list)
        
    def is_rate_limited(self, client_id: str) -> bool:
        """Vérifie si un client a dépassé la limite de requêtes"""
        now = time.time()
        
        # Nettoie les anciennes requêtes
        self.clients[client_id] = [
            req_time for req_time in self.clients[client_id]
            if now - req_time < self.window
        ]
        
        # Vérifie la limite
        if len(self.clients[client_id]) >= self.requests:
            logger.warning("rate_limit_exceeded", client_id=client_id)
            return True
            
        self.clients[client_id].append(now)
        return False

class SecurityManager:
    def __init__(self, max_secrets_per_ip: int):
        self.max_secrets_per_ip = max_secrets_per_ip
        self.ip_secrets: Dict[str, Set[str]] = defaultdict(set)
        
    def can_create_secret(self, ip: str) -> bool:
        """Vérifie si une IP peut créer un nouveau secret"""
        return len(self.ip_secrets[ip]) < self.max_secrets_per_ip
        
    def add_secret(self, ip: str, token: str) -> None:
        """Enregistre un nouveau secret pour une IP"""
        self.ip_secrets[ip].add(token)
        
    def remove_secret(self, ip: str, token: str) -> None:
        """Supprime un secret pour une IP"""
        self.ip_secrets[ip].discard(token)

def require_rate_limit(limiter: RateLimiter):
    """Décorateur pour appliquer le rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if limiter.is_rate_limited(request.remote_addr):
                abort(429)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_secret(secret: str) -> bool:
    """Valide le contenu d'un secret"""
    if not secret or len(secret.encode()) > 10 * 1024:  # 10 KB
        return False
    return True

def sanitize_secret(secret: str) -> str:
    """Nettoie le contenu d'un secret"""
    # Supprime les caractères de contrôle sauf les sauts de ligne
    return ''.join(char for char in secret if char >= ' ' or char in '\n\r')
