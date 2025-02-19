# Mesures de sécurité - OneTimeSecret

## 1. Protection des données

### Chiffrement en transit
- Utilisation obligatoire de HTTPS
- Configuration TLS stricte (TLS 1.3 uniquement)
- HSTS activé
- Certificats gérés avec rotation automatique

### Chiffrement au repos
- Chiffrement des secrets avec AES-256-GCM
- Clés de chiffrement dérivées avec PBKDF2
- Rotation périodique des clés maîtres
- Secrets stockés uniquement en mémoire, jamais sur disque

### Gestion des clés
- Clé maître stockée dans un gestionnaire de secrets (HashiCorp Vault)
- Dérivation unique de clé par secret
- Destruction sécurisée des clés après utilisation

## 2. Contrôles d'accès

### URLs de secrets
- Tokens aléatoires de 256 bits (43 caractères base64)
- Protection contre l'énumération par force brute
- Rate limiting par IP
- Vérification du timing constant pour les comparaisons

### Protection contre la relecture
- Suppression immédiate après lecture
- Vérification d'unicité stricte
- Expiration forcée après 24h
- Nettoyage périodique des secrets expirés

## 3. Protection de l'application

### En-têtes de sécurité
- Content-Security-Policy strict
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer

### Protection contre les injections
- Validation stricte des entrées
- Échappement contextuel en sortie
- Content-Type forcé pour tous les endpoints

### Limitation des ressources
- Taille maximale des secrets : 10 KB
- Rate limiting par IP : 10 requêtes/minute
- Maximum de secrets simultanés par IP
- Limitation de la mémoire totale utilisée

## 4. Monitoring et Audit

### Logging sécurisé
- Pas de données sensibles dans les logs
- Rotation des logs
- Format structuré pour analyse
- Timestamps précis et synchronisés

### Alertes de sécurité
- Détection des tentatives de force brute
- Alertes sur pic d'utilisation anormal
- Monitoring des erreurs d'authentification
- Vérification de l'intégrité des fichiers

## 5. Recommandations pour le déploiement

### Configuration serveur
- Utilisateur dédié avec privilèges minimaux
- Isolation dans un container
- Mise à jour automatique des dépendances
- Scan régulier des vulnérabilités

### Sauvegarde et récupération
- Pas de backup des secrets
- Plan de récupération documenté
- Procédure de rotation des clés
- Tests de restauration réguliers
