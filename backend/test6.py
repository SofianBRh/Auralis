import argparse
import json
import logging
import re
import sys
import os
import requests
import tempfile
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Set, List
from collections import defaultdict

# Pour éviter les erreurs liées à asyncio dans certains environnements
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass

import pyshark


# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# URL du serveur pour soumettre les résultats et récupérer le flag
FLAG_SERVER_URL = "http://93.127.203.48:5000/pcap/submit"
PCAP_FILENAME_URL = "http://93.127.203.48:5000/pcap/latest/filename"
PCAP_DOWNLOAD_URL = "http://93.127.203.48:5000/pcap/latest"


@dataclass
class HostInfo:
    """Structure de données représentant les informations d'un hôte réseau."""
    mac: Optional[str] = None
    ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    
    def clean_values(self) -> None:
        """Nettoie les valeurs de tous les champs en supprimant les séquences d'échappement ANSI."""
        ansi_pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        for attr_name in ['hostname', 'username', 'mac', 'ip']:
            value = getattr(self, attr_name)
            if value:
                cleaned_value = ansi_pattern.sub('', value).strip()
                setattr(self, attr_name, cleaned_value)


class ProtocolHandler:
    """Classe de base pour les handlers de protocoles spécifiques."""
    
    @classmethod
    def can_handle(cls, packet) -> bool:
        """Vérifie si le packet peut être traité par ce handler."""
        raise NotImplementedError("Les sous-classes doivent implémenter cette méthode")
    
    @classmethod
    def extract_info(cls, packet, host_info: HostInfo) -> bool:
        """Extrait les informations du paquet et met à jour l'objet HostInfo."""
        raise NotImplementedError("Les sous-classes doivent implémenter cette méthode")


class DHCPHandler(ProtocolHandler):
    """Handler pour traiter les paquets DHCP."""
    
    @classmethod
    def can_handle(cls, packet) -> bool:
        return hasattr(packet, 'dhcp') and hasattr(packet, 'eth') and hasattr(packet, 'ip')
    
    @classmethod
    def extract_info(cls, packet, host_info: HostInfo) -> bool:
        """Extrait les informations DHCP du paquet."""
        try:
            # Extraction MAC (toujours disponible si packet.eth existe)
            host_info.mac = packet.eth.src
            
            # Extraction IP
            if hasattr(packet.dhcp, 'ip_your') and packet.dhcp.ip_your != '0.0.0.0':
                host_info.ip = packet.dhcp.ip_your
            elif hasattr(packet.dhcp, 'ip_client') and packet.dhcp.ip_client != '0.0.0.0':
                host_info.ip = packet.dhcp.ip_client
            elif not host_info.ip:  # Ne pas écraser une IP déjà définie
                host_info.ip = packet.ip.src
            
            # Extraction hostname
            if hasattr(packet.dhcp, 'option_hostname'):
                host_info.hostname = packet.dhcp.option_hostname
            else:
                # Recherche d'autres champs contenant 'hostname'
                for field_name in dir(packet.dhcp):
                    if 'hostname' in field_name.lower():
                        hostname_value = getattr(packet.dhcp, field_name, None)
                        if hostname_value:
                            host_info.hostname = hostname_value
                            break
            
            return True
            
        except AttributeError as e:
            logger.debug(f"Erreur lors du traitement du paquet DHCP: {e}")
            return False


class HTTPHandler(ProtocolHandler):
    """Handler pour traiter les paquets HTTP."""
    
    @classmethod
    def can_handle(cls, packet) -> bool:
        return (hasattr(packet, 'http') and hasattr(packet, 'eth') and 
                hasattr(packet, 'ip') and hasattr(packet.http, 'accept_language'))
    
    @classmethod
    def extract_info(cls, packet, host_info: HostInfo) -> bool:
        """Extrait les informations HTTP du paquet."""
        try:
            # Mise à jour des informations de base
            host_info.mac = packet.eth.src
            host_info.ip = packet.ip.src
            
            # Extraction du nom d'utilisateur des cookies
            if hasattr(packet.http, 'cookie'):
                cookie = packet.http.cookie
                if 'username=' in cookie:
                    username = cookie.split('username=')[1].split(';')[0]
                    host_info.username = username
                    return True
            
            return False
                
        except AttributeError as e:
            logger.debug(f"Erreur lors du traitement du paquet HTTP: {e}")
            return False


class KerberosHandler(ProtocolHandler):
    """Handler pour traiter les paquets Kerberos."""
    
    @classmethod
    def can_handle(cls, packet) -> bool:
        return hasattr(packet, 'kerberos') and hasattr(packet, 'eth') and hasattr(packet, 'ip')
    
    @classmethod
    def extract_info(cls, packet, host_info: HostInfo) -> bool:
        """Extrait les informations Kerberos du paquet."""
        try:
            # Mise à jour des informations de base
            host_info.mac = packet.eth.src
            host_info.ip = packet.ip.src
            
            updated = False
            
            # Extraction du CNameString (nom d'utilisateur)
            if hasattr(packet.kerberos, 'CNameString'):
                cname = packet.kerberos.CNameString
                if cname.endswith('$'):
                    # Compte d'ordinateur
                    if not host_info.hostname:
                        host_info.hostname = cname
                        updated = True
                else:
                    # Compte utilisateur
                    host_info.username = cname
                    updated = True
            
            # Extraction du nom NetBIOS
            if hasattr(packet.kerberos, 'addresses'):
                for field in dir(packet.kerberos):
                    if field.startswith('addr_'):
                        addr_type_field = f"{field.replace('addr_', 'addr_type_')}"
                        if (hasattr(packet.kerberos, addr_type_field) and 
                            getattr(packet.kerberos, addr_type_field) == '20'):
                            netbios_name = getattr(packet.kerberos, field)
                            if netbios_name:
                                netbios_name = netbios_name.split('<')[0].strip()
                                host_info.hostname = netbios_name
                                updated = True
                                break
            
            # Méthode alternative: recherche dans les données brutes
            raw_data = str(packet)
            if 'NetBIOS Name:' in raw_data:
                try:
                    netbios_part = raw_data.split('NetBIOS Name:')[1].split('(')[0].strip()
                    netbios_name = netbios_part.split('<')[0].strip()
                    if netbios_name and len(netbios_name) > 1:
                        host_info.hostname = netbios_name
                        updated = True
                except Exception as e:
                    logger.debug(f"Erreur extraction NetBIOS: {e}")
            
            # Recherche de champs Kerberos supplémentaires
            for field in dir(packet.kerberos):
                if field.lower().startswith('cname') and field != 'CNameString':
                    value = getattr(packet.kerberos, field)
                    if value and not value.endswith('$') and not host_info.username:
                        host_info.username = value
                        updated = True
            
            return updated
                
        except AttributeError as e:
            logger.debug(f"Erreur lors du traitement du paquet Kerberos: {e}")
            return False


class NetworkAnalyzer:
    """
    Analyseur de réseau principal pour la capture et l'analyse des paquets.
    
    Cette classe gère la capture du trafic (en direct ou via fichier PCAP),
    coordonne le traitement des paquets par les différents handlers de protocoles,
    et génère un rapport avec les informations collectées.
    """
    
    # Filtres pour les protocoles d'intérêt
    DEFAULT_DISPLAY_FILTER = 'dhcp or http.accept_language or kerberos.CNameString and not nbns'
    
    def __init__(self, interface=None, pcap_file=None, output_file=None, verbose=False, auto_download=False):
        """
        Initialise l'analyseur réseau avec les paramètres fournis.
        
        Args:
            interface: Interface réseau pour la capture en direct
            pcap_file: Fichier PCAP à analyser
            output_file: Fichier JSON où sauvegarder les résultats
            verbose: Active la sortie de débogage si True
            auto_download: Télécharge automatiquement le dernier fichier PCAP disponible
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.output_file = output_file or 'network_hosts.json'
        self.hosts_info = defaultdict(HostInfo)
        self.flag = None
        self.auto_download = auto_download
        
        # Configuration du niveau de log selon verbose
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # Liste des handlers de protocoles
        self.protocol_handlers = [
            DHCPHandler,
            HTTPHandler,
            KerberosHandler
        ]
    
    def download_latest_pcap(self):
        """
        Télécharge le dernier fichier PCAP disponible sur le serveur.
        
        Returns:
            str: Chemin vers le fichier PCAP téléchargé ou None en cas d'erreur
        """
        try:
            # Récupération du nom du fichier
            logger.info("Récupération du nom du dernier fichier PCAP...")
            response_name = requests.get(PCAP_FILENAME_URL)
            
            if response_name.status_code != 200:
                logger.error(f"Impossible de récupérer le nom du fichier: {response_name.status_code} - {response_name.text}")
                return None
                
            filename = response_name.json().get("filename")
            if not filename:
                logger.error("Nom de fichier non trouvé dans la réponse")
                return None
                
            logger.info(f"Nom du fichier PCAP: {filename}")
            
            # Vérification si le fichier existe déjà
            if os.path.exists(filename):
                logger.info(f"Le fichier PCAP existe déjà: {filename}")
                return filename
            
            # Téléchargement du fichier
            logger.info(f"Téléchargement du fichier PCAP depuis {PCAP_DOWNLOAD_URL}...")
            response = requests.get(PCAP_DOWNLOAD_URL)
            
            if response.status_code != 200:
                logger.error(f"Erreur de téléchargement: {response.status_code} - {response.text}")
                return None
                
            # Écriture du fichier
            with open(filename, "wb") as f:
                f.write(response.content)
                
            logger.info(f"Fichier PCAP téléchargé avec succès: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement du fichier PCAP: {e}")
            return None
    
    def capture_live(self, duration=60):
        """
        Capture des paquets depuis une interface réseau en direct.
        
        Args:
            duration: Durée de la capture en secondes
        """
        try:
            logger.info(f"Démarrage de la capture sur {self.interface} pendant {duration} secondes...")
            capture = pyshark.LiveCapture(
                interface=self.interface, 
                display_filter=self.DEFAULT_DISPLAY_FILTER
            )
            capture.sniff(timeout=duration)
            self._process_packets(capture)
            
        except Exception as e:
            logger.error(f"Erreur lors de la capture en direct: {e}")
            sys.exit(1)
    
    def analyze_pcap(self):
        """Analyse un fichier pcap existant."""
        try:
            # Si le téléchargement automatique est activé, télécharger le dernier fichier PCAP
            if self.auto_download:
                downloaded_file = self.download_latest_pcap()
                if downloaded_file:
                    self.pcap_file = downloaded_file
                else:
                    logger.error("Impossible de télécharger le fichier PCAP. Abandon de l'analyse.")
                    sys.exit(1)
            
            logger.info(f"Analyse du fichier PCAP: {self.pcap_file}")
            capture = pyshark.FileCapture(
                self.pcap_file, 
                display_filter=self.DEFAULT_DISPLAY_FILTER
            )
            self._process_packets(capture)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du fichier PCAP: {e}")
            sys.exit(1)
    
    def _process_packets(self, capture):
        """
        Traite les paquets capturés et extrait les informations pertinentes.
        
        Args:
            capture: Objet de capture PyShark
        """
        packet_count = 0
        processed_count = 0
        
        try:
            for packet in capture:
                packet_count += 1
                
                # Traiter le paquet avec les handlers appropriés
                for handler in self.protocol_handlers:
                    if hasattr(packet, handler.__name__.replace('Handler', '').upper()):
                        if handler.can_handle(packet):
                            mac = packet.eth.src
                            if handler.extract_info(packet, self.hosts_info[mac]):
                                processed_count += 1
                
        except KeyboardInterrupt:
            logger.info("\nCapture interrompue par l'utilisateur")
        finally:
            logger.info(f"Traitement terminé: {packet_count} paquets analysés, "
                       f"{processed_count} paquets traités")
            self.save_results()
    
    def save_results(self):
        """Sauvegarde les résultats dans un fichier JSON avec uniquement la première entrée."""
        if not self.hosts_info:
            logger.info("Aucun hôte trouvé.")
            with open(self.output_file, 'w') as jsonfile:
                json.dump({}, jsonfile, indent=4)
            return

        # Obtenir uniquement la première entrée
        first_mac = next(iter(self.hosts_info))
        first_host_info = self.hosts_info[first_mac]
        
        # Nettoyer les valeurs
        first_host_info.clean_values()

        # Créer un dictionnaire avec seulement la première entrée
        single_host_dict = {
            'Host Information': asdict(first_host_info)
        }

        # Écrire dans le fichier JSON
        with open(self.output_file, 'w') as jsonfile:
            json.dump(single_host_dict, jsonfile, indent=4)
            
        logger.info(f"Résultat enregistré dans {self.output_file}")
        
        # Soumettre les résultats au serveur et récupérer le flag
        self._get_flag(single_host_dict)
        
        # Afficher les résultats
        self._display_results()

    def _get_flag(self, host_data):
        """
        Soumet les données collectées au serveur et récupère le flag.
        
        Args:
            host_data: Dictionnaire contenant les informations de l'hôte
        """
        try:
            # Extract the host information from the first entry
            host_info = host_data['Host Information']
            
            # Prepare the payload in the expected format
            payload = {
                "user_id": "dolores",  # Using the value from the example
                "lines": [
                    host_info['mac'] or "",         # MAC address
                    host_info['ip'] or "",          # IP address
                    host_info['hostname'] or "",    # Host name
                    host_info['username'] or ""     # Windows user account
                ]
            }
            
            logger.info(f"Envoi des données au serveur pour obtenir le flag...")
            response = requests.post(FLAG_SERVER_URL, json=payload)
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    if 'flag' in response_data:
                        self.flag = response_data['flag']
                        logger.info("Flag récupéré avec succès!")
                    else:
                        self.flag = response.text
                        logger.info("Réponse reçue du serveur (format non standard)")
                except json.JSONDecodeError:
                    # Si la réponse n'est pas au format JSON, on prend le texte brut
                    self.flag = response.text
                    logger.info("Réponse reçue du serveur (texte brut)")
            else:
                logger.error(f"Erreur lors de la récupération du flag: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Erreur lors de la communication avec le serveur: {e}")

    def _display_results(self):
        """Affiche uniquement le premier résultat dans le terminal et le flag s'il existe."""
        if not self.hosts_info:
            logger.info("\nAucun hôte trouvé.")
            return
            
        # Obtenir la première entrée
        first_mac = next(iter(self.hosts_info))
        info = self.hosts_info[first_mac]
        
        print("\n--- Informations sur l'hôte réseau ---")
        print(f"Adresse MAC: {info.mac or 'N/A'}")
        print(f"Adresse IP: {info.ip or 'N/A'}")
        print(f"Nom d'hôte: {info.hostname or 'N/A'}")
        print(f"Nom d'utilisateur: {info.username or 'N/A'}")
        
        # Afficher le flag s'il existe
        if self.flag:
            print("\n--- Flag ---")
            print(f"{self.flag}")


def parse_arguments():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(
        description='NetworkAnalyzer - Outil d\'extraction d\'informations sur les hôtes réseau',
        epilog='Exemple: %(prog)s -i eth0 -t 120 -o resultats.json'
    )
    
    # Groupe mutuellement exclusif pour les sources d'entrée
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument('-i', '--interface', 
                             help='Interface réseau pour la capture en direct')
    source_group.add_argument('-p', '--pcap', 
                             help='Fichier PCAP à analyser')
    source_group.add_argument('-d', '--download', action='store_true',
                             help='Télécharger et analyser automatiquement le dernier fichier PCAP disponible')
    
    # Options supplémentaires
    parser.add_argument('-t', '--time', type=int, default=60,
                       help='Durée de capture en secondes (défaut: 60)')
    parser.add_argument('-o', '--output', 
                       help='Fichier JSON de sortie (défaut: network_hosts.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Mode verbeux avec plus d\'informations de débogage')
    
    return parser.parse_args()


def main():
    """Point d'entrée principal du programme."""
    args = parse_arguments()
    
    # S'assurer que le nom de fichier se termine par .json
    output_file = args.output
    if output_file and not output_file.lower().endswith('.json'):
        output_file = f"{output_file.rsplit('.', 1)[0]}.json"
    
    # Initialiser l'analyseur
    analyzer = NetworkAnalyzer(
        interface=args.interface,
        pcap_file=args.pcap,
        output_file=output_file,
        verbose=args.verbose,
        auto_download=args.download
    )
    
    # Lancer l'analyse appropriée
    if args.interface:
        analyzer.capture_live(duration=args.time)
    elif args.pcap:
        analyzer.analyze_pcap()
    elif args.download:
        analyzer.analyze_pcap()  # Le téléchargement est géré en interne si auto_download=True
    else:
        # Par défaut, télécharger et analyser le dernier fichier PCAP
        analyzer.auto_download = True
        analyzer.analyze_pcap()


if __name__ == "__main__":
    main()