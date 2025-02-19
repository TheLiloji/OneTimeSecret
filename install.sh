#!/bin/bash

# Création de l'utilisateur système
sudo useradd -r -s /bin/false onetimesecret

# Création du répertoire d'installation
sudo mkdir -p /opt/onetimesecret
sudo chown onetimesecret:onetimesecret /opt/onetimesecret

# Copie des fichiers
sudo cp -r * /opt/onetimesecret/
sudo chown -R onetimesecret:onetimesecret /opt/onetimesecret/

# Création de l'environnement virtuel
cd /opt/onetimesecret
sudo -u onetimesecret python3 -m venv venv
sudo -u onetimesecret venv/bin/pip install -r requirements.txt

# Installation du service systemd
sudo cp onetimesecret.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable onetimesecret
sudo systemctl start onetimesecret

echo "Installation terminée. Le service est démarré et configuré pour démarrer au boot."
echo "Vérifiez le statut avec: sudo systemctl status onetimesecret"
