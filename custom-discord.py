#!/usr/bin/env python3

import sys
import requests
import json
import os
from datetime import datetime
import traceback

"""
ossec.conf configuration structure
 <integration>
     <name>custom-discord</name>
     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>
"""

# ----------------------------------------------------------------------
# 1. CONFIGURATION DU FILTRE
# ----------------------------------------------------------------------
# Liste des IDs de règles à TOUJOURS envoyer (même avec niveau bas)
ALWAYS_SEND_RULES = [
    "87105",       # Exemple: intégrité des fichiers critique
    "40704",
]

# Niveau minimum pour envoyer les autres alertes
MIN_LEVEL_FOR_OTHER_RULES = 12

# Configuration du logging
LOG_FILE = "/var/ossec/logs/integrations.log"  # Chemin standard Wazuh

# ----------------------------------------------------------------------
# 2. FONCTION DE LOGGING
# ----------------------------------------------------------------------
def log_message(level, message):
    """
    Écrit un message dans le fichier de log
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    
    try:
        # Vérifier si le répertoire existe
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Écrire dans le fichier de log
        with open(LOG_FILE, "a") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        # En dernier recours, afficher sur stderr
        sys.stderr.write(f"ERREUR LOGGING: {str(e)}\n")
        sys.stderr.write(f"Message original: {message}\n")

# ----------------------------------------------------------------------
# 3. LECTURE CONFIGURATION ET ALERTE
# ----------------------------------------------------------------------
try:
    # read configuration
    alert_file = sys.argv[1]
    user = sys.argv[2].split(":")[0]
    hook_url = sys.argv[3]
    
    log_message("INFO", f"Script démarré - Fichier: {alert_file}, Webhook: {hook_url[:30]}...")
    
except IndexError as e:
    log_message("ERROR", f"Arguments manquants: {str(e)}")
    log_message("ERROR", f"Usage: {sys.argv[0]} <fichier_alerte> <user> <webhook_url>")
    sys.exit(1)

# read alert file
try:
    with open(alert_file) as f:
        alert_json = json.loads(f.read())
    log_message("DEBUG", "Fichier alerte chargé avec succès")
except FileNotFoundError:
    log_message("ERROR", f"Fichier alerte non trouvé: {alert_file}")
    sys.exit(1)
except json.JSONDecodeError as e:
    log_message("ERROR", f"Erreur de parsing JSON: {str(e)}")
    sys.exit(1)
except Exception as e:
    log_message("ERROR", f"Erreur lecture fichier: {str(e)}")
    sys.exit(1)

# ----------------------------------------------------------------------
# 4. FILTRAGE DES ALERTES
# ----------------------------------------------------------------------
try:
    rule_id = alert_json["rule"]["id"]
    alert_level = alert_json["rule"]["level"]
    
    log_message("DEBUG", f"Règle: {rule_id}, Niveau: {alert_level}")
    
    # Déterminer si on doit envoyer l'alerte
    should_send = False
    reason = ""
    
    # Cas 1: Règle dans la liste blanche
    if rule_id in ALWAYS_SEND_RULES:
        should_send = True
        reason = f"Règle dans liste blanche: {rule_id}"
        log_message("INFO", reason)
        
    # Cas 2: Niveau de sévérité élevé
    elif alert_level >= MIN_LEVEL_FOR_OTHER_RULES:
        should_send = True
        reason = f"Niveau {alert_level} >= {MIN_LEVEL_FOR_OTHER_RULES}"
        log_message("INFO", reason)
        
    # Sinon, on ignore
    else:
        reason = f"Ignoré - Règle: {rule_id}, Niveau: {alert_level} (seuil: {MIN_LEVEL_FOR_OTHER_RULES})"
        log_message("INFO", reason)
        sys.exit(0)
        
except KeyError as e:
    log_message("ERROR", f"Champ manquant dans l'alerte: {str(e)}")
    sys.exit(1)

# ----------------------------------------------------------------------
# 5. EXTRACTION DES DONNÉES DE L'ALERTE
# ----------------------------------------------------------------------
try:
    # Règle
    rule_description = alert_json["rule"]["description"]
    rule_groups = alert_json["rule"].get("groups", [])
    rule_firedtimes = alert_json["rule"].get("firedtimes", 1)
    
    # MITRE (si présent)
    mitre_info = alert_json["rule"].get("mitre", {})
    mitre_ids = mitre_info.get("id", [])
    mitre_techniques = mitre_info.get("technique", [])
    mitre_tactics = mitre_info.get("tactic", [])
    
    # Agent
    if "agentless" in alert_json:
        agent_name = "agentless"
        agent_ip = "N/A"
    else:
        agent_name = alert_json["agent"].get("name", "N/A")
        agent_ip = alert_json["agent"].get("ip", "N/A")
    
    # Source IP (si disponible)
    src_ip = alert_json.get("data", {}).get("srcip", "N/A")
    dst_user = alert_json.get("data", {}).get("dstuser", "N/A")
    src_port = alert_json.get("data", {}).get("srcport", "N/A")
    
    # Autres informations
    full_log = alert_json.get("full_log", "Non disponible")
    timestamp = alert_json.get("timestamp", "N/A")
    location = alert_json.get("location", "N/A")
    manager_name = alert_json.get("manager", {}).get("name", "N/A")
    
    log_message("DEBUG", f"Données extraites - Agent: {agent_name}, Source IP: {src_ip}")
    
except Exception as e:
    log_message("ERROR", f"Erreur extraction données: {str(e)}")
    sys.exit(1)

# ----------------------------------------------------------------------
# 6. DÉTERMINATION DE LA COULEUR
# ----------------------------------------------------------------------
if rule_id in ALWAYS_SEND_RULES and alert_level < 8:
    # Règles spéciales avec niveau bas = orange
    color = "16753920"
elif alert_level < 5:
    # green
    color = "5763719"
elif alert_level >= 5 and alert_level <= 7:
    # yellow
    color = "16705372"
elif alert_level >= 8 and alert_level <= 11:
    # orange
    color = "15105570"
else:
    # red (niveau 12+)
    color = "15548997"

# ----------------------------------------------------------------------
# 7. PRÉPARATION DES FIELDS POUR DISCORD
# ----------------------------------------------------------------------
fields = [
    {
        "name": "Agent",
        "value": agent_name,
        "inline": True
    },
    {
        "name": "Niveau",
        "value": str(alert_level),
        "inline": True
    },
    {
        "name": "Déclenchée",
        "value": f"{rule_firedtimes} fois",
        "inline": True
    }
]

# Ajouter IP source si disponible
if src_ip != "N/A":
    fields.extend([
        {
            "name": "IP Source",
            "value": src_ip,
            "inline": True
        },
        {
            "name": "Port Source",
            "value": str(src_port) if src_port != "N/A" else "N/A",
            "inline": True
        },
        {
            "name": "Utilisateur",
            "value": dst_user if dst_user != "N/A" else "N/A",
            "inline": True
        }
    ])

# Ajouter IP de l'agent si différente
if agent_ip != "N/A" and agent_ip != src_ip:
    fields.append({
        "name": "IP Agent",
        "value": agent_ip,
        "inline": True
    })

# Ajouter les groupes de la règle
if rule_groups:
    fields.append({
        "name": "Groupes",
        "value": ", ".join(rule_groups),
        "inline": False
    })

# Ajouter les informations MITRE si présentes
if mitre_ids:
    fields.extend([
        {
            "name": "MITRE ID",
            "value": ", ".join(mitre_ids),
            "inline": True
        },
        {
            "name": "Technique",
            "value": ", ".join(mitre_techniques) if mitre_techniques else "N/A",
            "inline": True
        },
        {
            "name": "Tactique",
            "value": ", ".join(mitre_tactics) if mitre_tactics else "N/A",
            "inline": True
        }
    ])

# Ajouter d'autres métadonnées
fields.extend([
    {
        "name": "Location",
        "value": location,
        "inline": True
    },
    {
        "name": "Manager",
        "value": manager_name,
        "inline": True
    },
    {
        "name": "Horodatage",
        "value": timestamp,
        "inline": False
    }
])

# Ajouter le log complet (tronqué si trop long)
if full_log and full_log != "Non disponible":
    truncated_log = full_log[:1000] + "..." if len(full_log) > 1000 else full_log
    fields.append({
        "name": "Log",
        "value": f"```\n{truncated_log}\n```",
        "inline": False
    })

# ----------------------------------------------------------------------
# 8. DÉTERMINATION DU TITRE
# ----------------------------------------------------------------------
if rule_id in ALWAYS_SEND_RULES:
    title_prefix = " ALERTE IMPORTANTE"
elif alert_level >= 12:
    title_prefix = " ALERTE CRITIQUE"
elif alert_level >= 8:
    title_prefix = " ALERTE ÉLEVÉE"
else:
    title_prefix = " ALERTE"

special_indicator = " (Règle surveillée)" if rule_id in ALWAYS_SEND_RULES else ""
title = f"{title_prefix} - Règle {rule_id}{special_indicator}"

# ----------------------------------------------------------------------
# 9. CONSTRUCTION DU PAYLOAD
# ----------------------------------------------------------------------
payload = json.dumps({
    "content": "",  # Vous pouvez ajouter @here ou @role ici
    "embeds": [
        {
            "title": title,
            "color": int(color),
            "description": f"**{rule_description}**\nRaison: {reason}",
            "fields": fields,
            "footer": {
                "text": f"Wazuh - Filtre: Niveau ≥ {MIN_LEVEL_FOR_OTHER_RULES} ou règles spécifiques"
            }
        }
    ]
})

# ----------------------------------------------------------------------
# 10. ENVOI À DISCORD
# ----------------------------------------------------------------------
try:
    log_message("INFO", f"Envoi alerte {rule_id} (niveau {alert_level}) vers Discord...")
    
    r = requests.post(
        hook_url, 
        data=payload, 
        headers={"content-type": "application/json"},
        timeout=10
    )
    
    if r.status_code in [200, 204]:
        log_message("SUCCESS", f"Alerte {rule_id} envoyée avec succès à Discord")
    else:
        log_message("ERROR", f"Erreur Discord: HTTP {r.status_code} - {r.text}")
        
except requests.exceptions.Timeout:
    log_message("ERROR", f"Timeout lors de l'envoi à Discord")
except requests.exceptions.ConnectionError:
    log_message("ERROR", f"Erreur de connexion à Discord")
except Exception as e:
    log_message("ERROR", f"Erreur inattendue: {str(e)}")
    log_message("DEBUG", f"Traceback: {traceback.format_exc()}")

sys.exit(0)
