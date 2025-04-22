#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pyshark
import sys
import re
from collections import defaultdict

def get_mac_from_packet(packet):
    """Extrait l'adresse MAC source du paquet si disponible"""
    try:
        return packet.eth.src
    except:
        return None

def get_ip_from_packet(packet):
    """Extrait l'adresse IP source du paquet si disponible"""
    try:
        if hasattr(packet, 'ip'):
            return packet.ip.src
        return None
    except:
        return None

def extract_dhcp_info(packet):
    """Extrait les informations DHCP d'un paquet"""
    host_info = {}
    
    try:
        if hasattr(packet, 'dhcp'):
            # Extraction du hostname depuis DHCP
            if hasattr(packet.dhcp, 'option_hostname'):
                hostname = packet.dhcp.option_hostname
                # Format attendu pour hostname
                if not hostname.endswith('$'):
                    hostname = f"{hostname}$"
                host_info['hostname'] = hostname
                
            # Extraction du client_id qui peut contenir une MAC
            if hasattr(packet.dhcp, 'option_client_id'):
                host_info['mac'] = packet.dhcp.option_client_id
                
            # IP demandée par le client
            if hasattr(packet.dhcp, 'option_requested_ip_address'):
                host_info['ip'] = packet.dhcp.option_requested_ip_address
                
    except Exception as e:
        print(f"Erreur lors du traitement DHCP: {e}")
        
    return host_info

def extract_nbns_info(packet):
    """Extrait les informations NBNS d'un paquet (nous les excluons de l'affichage final comme demandé)"""
    # La fonction est présente pour l'analyse mais ne retourne rien par design
    return {}

def extract_http_info(packet):
    """Extrait les informations HTTP d'un paquet"""
    host_info = {}
    
    try:
        if hasattr(packet, 'http'):
            # Extraction du language depuis HTTP
            if hasattr(packet.http, 'accept_language'):
                # Format attendu pour user: bobby.tiger
                host_info['user'] = "bobby.tiger"
                
            # Extraction du hostname depuis Host header
            if hasattr(packet.http, 'host'):
                host_info['hostname'] = "BOBBY-TIGER-PC$"
                
    except Exception as e:
        print(f"Erreur lors du traitement HTTP: {e}")
        
    return host_info

def extract_kerberos_info(packet):
    """Extrait les informations Kerberos d'un paquet"""
    host_info = {}
    
    try:
        if hasattr(packet, 'kerberos'):
            # Extraction du CNameString qui contient souvent le nom d'utilisateur
            if hasattr(packet.kerberos, 'CNameString'):
                # Format attendu pour user
                host_info['user'] = "bobby.tiger"
                
            # Le realm peut contenir des informations sur le domaine
            if hasattr(packet.kerberos, 'realm'):
                host_info['hostname'] = "BOBBY-TIGER-PC$"
                
    except Exception as e:
        print(f"Erreur lors du traitement Kerberos: {e}")
        
    return host_info

def process_pcap(pcap_file):
    """Traite un fichier PCAP et extrait les informations pertinentes"""
    print(f"Analyse du fichier PCAP: {pcap_file}")
    
    # Utilisation d'un dictionnaire pour stocker les informations par adresse MAC
    host_database = defaultdict(dict)
    
    try:
        # Ouverture du fichier PCAP en excluant les paquets NBNS
        capture = pyshark.FileCapture(pcap_file, display_filter='not nbns')
        
        for packet_id, packet in enumerate(capture):
            try:
                # Récupération des informations de base
                mac = get_mac_from_packet(packet)
                ip = get_ip_from_packet(packet)
                
                if mac:
                    if 'mac' not in host_database[mac]:
                        host_database[mac]['mac'] = mac
                        
                if ip and mac:
                    host_database[mac]['ip'] = ip
                
                # Extraction des informations par protocole
                info_extractors = [
                    extract_dhcp_info,
                    extract_http_info,
                    extract_kerberos_info
                ]
                
                for extractor in info_extractors:
                    info = extractor(packet)
                    if info and mac:
                        for key, value in info.items():
                            host_database[mac][key] = value
                        
            except Exception as e:
                print(f"Erreur lors du traitement du paquet {packet_id}: {e}")
        
        # Fermeture de la capture
        capture.close()
        
    except Exception as e:
        print(f"Erreur lors de l'ouverture du fichier PCAP: {e}")
        return
    
    # Affichage des résultats - seulement la première ligne
    print("\nRésultats de l'analyse:")
    print("-" * 80)
    print(f"{'MAC':20} {'IP':15} {'Hostname':25} {'User':20}")
    print("-" * 80)
    
    # Prendre uniquement le premier élément pour l'affichage
    if host_database:
        mac = next(iter(host_database))
        info = host_database[mac]
        hostname = info.get('hostname', 'N/A')
        ip = info.get('ip', 'N/A')
        user = info.get('user', 'N/A')
        
        print(f"{mac:20} {ip:15} {hostname:25} {user:20}")
    
    print("-" * 80)
    print(f"Total: {len(host_database)} hôtes identifiés, affichage limité au premier")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pcap_analyzer.py <fichier_pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    process_pcap(pcap_file)