from flask import Flask, render_template, request, jsonify
import requests
from dotenv import load_dotenv
import os

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

app = Flask(__name__)

# Récupérer les données sensibles depuis les variables d'environnement
API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

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
    

# VIRUS TOTAL API
API_KEY_VT = "f4bf09e31b72bc0572320e6a2a3193f4133b39353424087a7e989acde7c6b47c"

@app.route("/analyse_ip")
def analyse_ip():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP manquante"}), 400

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY_VT
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return jsonify({"error": "Erreur avec VirusTotal"}), response.status_code

    data = response.json()

    #récupérer juste le nombre de détections "malicious"
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0)

    # Renvoie un niveau simple pour le front
    criticity = min(malicious_count * 20, 100)  # niveau sur 100, simple échelle

    return jsonify({
        "ip": ip,
        "malicious": malicious_count,
        "criticity": criticity
    })
    

# --- MOCK DATA à remplacer par la vraie analyse plus tard (les retours à envoyer au front)---
mock_data = {
    "user_name": "prince",
    "ip_suspect": "192.168.1.156",
    "machine": "hp_buro",
    "protocols": "TCP, UDP, HTTP, DNS",
    "packet_count": 1087,
    "message": "Cet IP a été repérée en train de faire des trucs louches : elle envoie plein de requêtes bizarres à des sites suspects, un peu comme quelqu’un qui toque à toutes les portes d’un quartier à 3h du matin. Notre système l’a croisée plusieurs fois dans des listes noires connues. Bref, c’est clairement pas net. Prudence recommandée !",
    # "alerts": [
    #     {"ip": "192.168.0.101", "description": "Comportement suspect détecté sur le port 4444."},
    #     {"ip": "10.0.0.8", "description": "Connexion anormale à un domaine blacklisté."}
    # ],
    "date": "2023-10-01 12:34:56",
    "hostnames": "example.com",
    "flag": "FLAG{auralis_detected_intrusion}"
}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
