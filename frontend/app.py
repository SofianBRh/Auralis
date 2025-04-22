from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Configuration de l'API Mistral (remplace par ta clé API)
API_KEY = "695f4799-c556-476c-9f04-25b7b192b4cd"
BASE_URL = "https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1"

@app.route('/')
def index():
    return render_template('index.html')

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
