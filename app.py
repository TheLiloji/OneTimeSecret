import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import structlog
from config import Config
from crypto import SecretCrypto, generate_token
from security import RateLimiter, SecurityManager, require_rate_limit, validate_secret, sanitize_secret

# Configuration du logging
logger = structlog.get_logger()

app = Flask(__name__)
app.config.from_object(Config)

# Configuration de la sécurité HTTPS
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy=Config.SECURITY_HEADERS['Content-Security-Policy']
)

# Initialisation des gestionnaires de sécurité
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

rate_limiter = RateLimiter(
    requests=Config.RATE_LIMIT_REQUESTS,
    window=Config.RATE_LIMIT_WINDOW
)

security_manager = SecurityManager(
    max_secrets_per_ip=Config.MAX_SECRETS_PER_IP
)

# Initialisation du crypto
master_key = os.urandom(Config.ENCRYPTION_KEY_LENGTH)
crypto = SecretCrypto(master_key)

# Structure de données pour les secrets
secrets = {}

@app.context_processor
def inject_year():
    return {'year': datetime.now().year}

@app.before_request
def before_request():
    """Middleware pour ajouter les en-têtes de sécurité"""
    for header, value in Config.SECURITY_HEADERS.items():
        if header != 'Content-Security-Policy':  # Déjà géré par Talisman
            response = app.make_default_options_response()
            response.headers[header] = value

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
@limiter.limit("10 per minute")
@require_rate_limit(rate_limiter)
def create():
    secret = request.form.get('secret')
    
    # Validation et nettoyage
    if not validate_secret(secret):
        logger.warning("invalid_secret_submitted", ip=request.remote_addr)
        return render_template('error.html', message="Secret invalide. Taille maximale : 10 KB")
    
    secret = sanitize_secret(secret)
    
    # Vérification des limites par IP
    if not security_manager.can_create_secret(request.remote_addr):
        logger.warning("max_secrets_exceeded", ip=request.remote_addr)
        return render_template('error.html', message="Limite de secrets atteinte pour votre IP")
    
    # Génération du token et chiffrement
    token = generate_token()
    ciphertext, salt, nonce = crypto.encrypt_secret(secret)
    
    # Stockage du secret
    secrets[token] = {
        'data': {
            'ciphertext': ciphertext,
            'salt': salt,
            'nonce': nonce
        },
        'expires': datetime.now() + Config.SECRET_LIFETIME,
        'ip': request.remote_addr
    }
    
    security_manager.add_secret(request.remote_addr, token)
    logger.info("secret_created", token=token[:8] + '...')
    
    return render_template('created.html', token=token)

@app.route('/secret/<token>')
@limiter.limit("10 per minute")
@require_rate_limit(rate_limiter)
def view_secret(token):
    if token not in secrets:
        logger.info("secret_not_found", token=token[:8] + '...')
        return render_template('error.html', message="Ce secret n'existe pas ou a déjà été lu")
    
    secret_data = secrets[token]
    
    # Vérification de l'expiration
    if datetime.now() > secret_data['expires']:
        del secrets[token]
        security_manager.remove_secret(secret_data['ip'], token)
        logger.info("secret_expired", token=token[:8] + '...')
        return render_template('error.html', message="Ce secret a expiré")
    
    # Déchiffrement du secret
    decrypted = crypto.decrypt_secret(
        secret_data['data']['ciphertext'],
        secret_data['data']['salt'],
        secret_data['data']['nonce']
    )
    
    if decrypted is None:
        logger.error("secret_decryption_failed", token=token[:8] + '...')
        return render_template('error.html', message="Impossible de déchiffrer le secret")
    
    # Suppression du secret après lecture
    del secrets[token]
    security_manager.remove_secret(secret_data['ip'], token)
    logger.info("secret_viewed", token=token[:8] + '...')
    
    return render_template('view.html', secret=decrypted)

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning("rate_limit_exceeded", ip=request.remote_addr)
    return render_template('error.html', message="Trop de requêtes. Veuillez réessayer plus tard."), 429

if __name__ == '__main__':
    # En production, on écoute sur localhost uniquement
    # Le reverse proxy s'occupera de rediriger le trafic
    app.run(
        host='127.0.0.1',
        port=5000,
        ssl_context=None  # Pas besoin de SSL car géré par le reverse proxy
    )
