# OneTimeSecret - Terensys

Service de partage sécurisé de secrets à usage unique.

## Prérequis

- Ubuntu Server
- Python 3.8+
- Accès root ou sudo

## Installation

1. Transférez tous les fichiers vers votre serveur :
```bash
scp -r * user@votre-serveur:/tmp/onetimesecret/
```

2. Connectez-vous à votre serveur et rendez les scripts exécutables :
```bash
cd /tmp/onetimesecret
chmod +x install.sh start.sh
```

3. Lancez le script d'installation :
```bash
sudo ./install.sh
```

## Vérification

1. Vérifiez que le service est en cours d'exécution :
```bash
sudo systemctl status onetimesecret
```

2. Vérifiez les logs si nécessaire :
```bash
sudo journalctl -u onetimesecret -f
```

## Configuration

Le service est configuré pour :
- Écouter sur localhost:5000
- Utiliser le domaine ots.terensys.net
- Démarrer automatiquement au boot
- Redémarrer automatiquement en cas de crash

## Sécurité

- Le service s'exécute sous un utilisateur dédié (onetimesecret)
- Les fichiers sont isolés dans /opt/onetimesecret
- L'utilisateur n'a pas de shell
- Le service est configuré pour redémarrer automatiquement

## Maintenance

- Redémarrer le service :
```bash
sudo systemctl restart onetimesecret
```

- Voir les logs :
```bash
sudo journalctl -u onetimesecret -f
```

- Mettre à jour l'application :
```bash
cd /opt/onetimesecret
sudo -u onetimesecret venv/bin/pip install -r requirements.txt
sudo systemctl restart onetimesecret
```
#   O n e T i m e S e c r e t  
 