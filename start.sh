#!/bin/bash

# Activation de l'environnement virtuel
source venv/bin/activate

# Configuration de l'environnement
export FLASK_APP=app.py
export FLASK_ENV=production
export SERVER_NAME=ots.terensys.net

# Démarrage de l'application
python app.py
