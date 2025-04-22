from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Configuration de l'API Mistral (remplace par ta clé API)
API_KEY = "osenv"
BASE_URL = "https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1"

@app.route('/request')
def request_page():
    return render_template('request.html')

@app.route('/')
def dashboard():
    return render_template('dashboard.html', **mock_data)

@app.route('/request_mistral', methods=['POST'])
def request_mistral():
    model = request.form['model']
    messages = request.form['messages']
    temperature = float(request.form['temperature'])
    max_tokens = int(request.form['max_tokens'])

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
        return render_template('index.html', response=response_data["choices"][0]["message"]["content"])
    except requests.exceptions.RequestException as e:
        return render_template('index.html', response="Une erreur est survenue lors de la requête.")
    



# --- MOCK DATA à remplacer par la vraie analyse plus tard (les retours à envoyer au front)---
mock_data = {
    "user_name": "prince",
    "source_ip_count": 42,
    "destination_ip_count": 37,
    "protocols": "TCP, UDP, HTTP, DNS",
    "packet_count": 1087,
    "ai_analysis_result": "Activité réseau normale détectée. Aucun comportement malveillant repéré dans ce segment.",
    "alerts": [
        {"ip": "192.168.0.101", "description": "Comportement suspect détecté sur le port 4444."},
        {"ip": "10.0.0.8", "description": "Connexion anormale à un domaine blacklisté."}
    ],
    "flag": "FLAG{auralis_detected_intrusion}"
}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
