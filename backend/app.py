from fastapi import FastAPI
from fastapi.openapi.models import APIKey
import requests
import pyshark
import os
from dotenv import load_dotenv

# Charger les variables d'environnement depuis .env
load_dotenv()

app = FastAPI()

# Variables d'environnement
API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

@app.get("/")
def read_root():
    return {"message": "Bienvenue dans l'API FastAPI avec Swagger"}

@app.get("/docs")
def get_swagger_docs():
    return {"message": "Accédez à la documentation Swagger ici: /docs"}

@app.post("/request_mistral")
async def request_mistral(model: str, messages: str, temperature: float = 0.3, max_tokens: int = 256):
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": "Vous êtes un assistant utile."}, {"role": "user", "content": messages}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "top_p": 1
    }

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(f"{BASE_URL}/chat/completions", json=payload, headers=headers)
        response_data = response.json()
        return response_data["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# La documentation Swagger est automatiquement générée et disponible à l'adresse "/docs" par défaut