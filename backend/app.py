from fastapi import FastAPI, HTTPException
import requests
import pyshark
import os
import time
from openai import OpenAI

app = FastAPI()

# Configuration de l'API Mistral
client = OpenAI(
    base_url="https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1",
    api_key=OS.getenv("OPENAI_API_KEY")
)

# Fonction pour télécharger le fichier PCAP
def download_pcap():
    url = "http://93.127.203.48:5000/pcap/latest"
    response = requests.get(url)
    if response.status_code == 200:
        filename = response.headers.get("Content-Disposition").split("filename=")[1]
        with open(f"/app/{filename}", "wb") as f:
            f.write(response.content)
        return filename
    else:
        raise HTTPException(status_code=500, detail="Erreur lors du téléchargement du fichier PCAP.")

# Vérification si le nom du fichier a changé
def check_for_new_pcap():
    current_file = "/app/latest.pcap"
    new_file = download_pcap()
    if current_file != new_file:
        return new_file
    return None

# Fonction pour analyser les données du fichier PCAP
def analyse_pcap(filename):
    cap = pyshark.FileCapture(f"/app/{filename}")
    packets_info = []

    for packet in cap:
        packet_info = {
            "src_ip": packet.ip.src if hasattr(packet, 'ip') else "N/A",
            "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else "N/A",
            "protocol": packet.transport_layer if hasattr(packet, 'transport_layer') else "N/A",
            "time": packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else "N/A",
            "packet_analysis": str(packet)  # Ajouter des informations détaillées sur le paquet
        }
        packets_info.append(packet_info)

    return packets_info

# Endpoint pour récupérer et analyser le PCAP
@app.get("/analyse_pcap")
async def analyse():
    try:
        new_pcap = check_for_new_pcap()
        if new_pcap:
            packets_info = analyse_pcap(new_pcap)
            # Utilisation de l'API Mistral pour enrichir l'analyse (ici un exemple d'enrichissement)
            response = client.chat.completions.create(
                model="mistral-nemo-instruct-2407",
                messages=[
                    {"role": "system", "content": "Vous êtes un assistant de sécurité."},
                    {"role": "user", "content": str(packets_info)}
                ],
                max_tokens=256,
                temperature=0.3,
                top_p=1,
            )
            return {"status": "success", "data": packets_info, "ai_analysis": response.choices[0].message.content}
        else:
            return {"status": "no_change", "message": "Le fichier PCAP n'a pas changé."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
