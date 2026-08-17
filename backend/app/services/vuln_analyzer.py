"""Rule-based vulnerability analyzer."""
from sqlalchemy.orm import Session
from app.models.scan import Host
from app.models.vulnerability import Vulnerability, Severity

# (service_name, port, severity, title, description, recommendation, cvss, impact)
RULES: list[tuple] = [
    ("ftp",           21,    Severity.high,     "FTP en clair",          "FTP transmet les données sans chiffrement.",           "Remplacer FTP par SFTP ou FTPS.",                          7.5, "Interception des identifiants et données en transit."),
    ("telnet",        23,    Severity.critical, "Telnet non chiffré",    "Telnet expose les credentials en clair.",              "Désactiver Telnet et utiliser SSH.",                        9.8, "Prise de contrôle complète du système via sniffing réseau."),
    ("smtp",          25,    Severity.medium,   "SMTP ouvert",           "Risque de relais ouvert (open relay).",                "Configurer l'authentification SMTP et SPF/DKIM.",           5.3, "Utilisation pour envoi de spam ou phishing."),
    ("domain",        53,    Severity.medium,   "DNS exposé",            "Serveur DNS accessible, risque d'amplification.",      "Restreindre les requêtes récursives aux clients internes.", 5.3, "Amplification DDoS et empoisonnement du cache DNS."),
    ("http",          80,    Severity.medium,   "HTTP non chiffré",      "Trafic web non chiffré.",                              "Forcer HTTPS avec redirection 301.",                        5.3, "Interception des sessions et données utilisateurs."),
    ("msrpc",         135,   Severity.medium,   "MSRPC exposé",          "Service RPC Windows exposé sur le réseau.",            "Filtrer le port 135 au niveau du firewall.",                5.3, "Vecteur d'attaque pour propagation de vers réseau."),
    ("netbios",       139,   Severity.medium,   "NetBIOS exposé",        "NetBIOS peut exposer des informations réseau.",         "Désactiver NetBIOS si non nécessaire.",                     4.3, "Divulgation de noms de machines et partages réseau."),
    ("smb",           445,   Severity.critical, "SMB exposé",            "SMBv1/EternalBlue peut permettre une RCE.",            "Désactiver SMBv1, appliquer KB4012212.",                    9.8, "Exécution de code à distance, déploiement de ransomware (WannaCry)."),
    ("microsoft-ds",  445,   Severity.critical, "SMB exposé",            "SMBv1/EternalBlue peut permettre une RCE.",            "Désactiver SMBv1, appliquer KB4012212.",                    9.8, "Exécution de code à distance, déploiement de ransomware (WannaCry)."),
    ("vmware",        902,   Severity.high,     "VMware Auth exposé",    "Service d'authentification VMware accessible.",        "Restreindre l'accès au réseau de gestion uniquement.",     7.5, "Accès non autorisé aux machines virtuelles."),
    ("vmware",        912,   Severity.high,     "VMware Auth exposé",    "Service d'authentification VMware accessible.",        "Restreindre l'accès au réseau de gestion uniquement.",     7.5, "Accès non autorisé aux machines virtuelles."),
    ("ms-sql-s",      1433,  Severity.high,     "MSSQL exposé",          "Base de données SQL exposée sur le réseau.",           "Restreindre l'accès par firewall.",                         7.5, "Exfiltration de données sensibles, injection SQL directe."),
    ("oracle",        1521,  Severity.high,     "Oracle DB exposé",      "Base de données Oracle accessible sur le réseau.",     "Restreindre l'accès par firewall, activer Oracle Audit.",  7.5, "Accès non autorisé aux données critiques de l'entreprise."),
    ("mysql",         3306,  Severity.high,     "MySQL exposé",          "Base de données MySQL accessible.",                    "Lier MySQL à 127.0.0.1 uniquement.",                        7.5, "Exfiltration ou destruction de bases de données."),
    ("rdp",           3389,  Severity.high,     "RDP exposé",            "Bureau à distance exposé, risque de brute-force.",     "Activer NLA, limiter l'accès VPN.",                         8.1, "Prise de contrôle à distance du poste ou serveur."),
    ("ms-wbt-server", 3389,  Severity.high,     "RDP exposé",            "Bureau à distance exposé, risque de brute-force.",     "Activer NLA, limiter l'accès VPN.",                         8.1, "Prise de contrôle à distance du poste ou serveur."),
    ("vnc",           5900,  Severity.high,     "VNC exposé",            "Accès bureau à distance non sécurisé.",                "Utiliser un tunnel SSH pour VNC.",                          8.1, "Accès visuel et contrôle complet du bureau sans authentification forte."),
    (None,            8080,  Severity.low,      "Port 8080 ouvert",      "Service web alternatif détecté.",                      "Vérifier que le service est intentionnel.",                 3.1, "Exposition d'une application web potentiellement non sécurisée."),
    ("mongodb",       27017, Severity.critical, "MongoDB exposé",        "MongoDB sans authentification par défaut.",            "Activer l'authentification et restreindre le port.",        9.8, "Lecture, modification ou suppression complète de la base de données."),
    ("redis",         6379,  Severity.critical, "Redis exposé",          "Redis sans authentification.",                         "Configurer requirepass et restreindre l'accès.",            9.8, "Exécution de commandes arbitraires et exfiltration de données en cache."),
    ("elasticsearch", 9200,  Severity.high,     "Elasticsearch exposé",  "Index potentiellement lisibles.",                      "Activer X-Pack Security.",                                  7.5, "Accès public aux données indexées sans authentification."),
]


def analyze_host(host: Host, db: Session) -> None:
    seen: set[str] = set()
    for (svc, port_num, severity, title, desc, rec, cvss, impact) in RULES:
        for p in host.ports:
            if p.port_number != port_num:
                continue
            match_service = (svc is None) or (p.service and svc.lower() in p.service.lower())
            if match_service and title not in seen:
                seen.add(title)
                db.add(Vulnerability(
                    host_id=host.id,
                    severity=severity,
                    title=title,
                    description=desc,
                    recommendation=rec,
                    cvss_score=cvss,
                    port_number=p.port_number,
                    impact=impact,
                ))
