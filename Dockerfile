# Image Python légère
FROM python:3.11-slim

# Répertoire de travail dans le container
WORKDIR /app

# Copie des dépendances en premier (optimise le cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste de l'application
COPY . .

# Port exposé
EXPOSE 5000

# Lancement de Flask
CMD ["python", "app.py"]
