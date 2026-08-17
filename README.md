# NexusSecure

Plateforme professionnelle d'audit et de sécurisation des réseaux informatiques.

---

## Stack technique

- **Backend** : Python 3.12, FastAPI, SQLAlchemy, Alembic, JWT
- **Frontend** : Bootstrap 5, Chart.js, Jinja2
- **Scanner** : python-nmap (wrapper Nmap)
- **Rapports** : ReportLab (PDF)
- **DB** : SQLite (dev) / PostgreSQL (prod)

---

## Installation Linux (Ubuntu/Debian)

### 1. Prérequis système

```bash
sudo apt update && sudo apt install -y python3.12 python3.12-venv python3-pip nmap
```

### 2. Cloner le projet

```bash
git clone https://github.com/votre-org/nexussecure.git
cd nexussecure
```

### 3. Environnement Python

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configuration

```bash
cp ../.env.example ../.env
# Éditer .env : SECRET_KEY, FIRST_ADMIN_PASSWORD, DATABASE_URL
nano ../.env
```

Générer une clé secrète sécurisée :
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Lancer l'application

```bash
# Depuis backend/
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Accéder à `http://localhost:8000`  
Documentation API : `http://localhost:8000/docs`

---

## Installation avec Docker

```bash
cp .env.example .env
# Éditer .env
docker compose up --build
```

---

## Migrations Alembic

`alembic.ini` vit à la racine du projet, à côté du dossier `alembic/` qu'il référence —
les commandes s'exécutent donc depuis la racine, pas depuis `backend/`.

```bash
# Depuis la racine du dépôt
# Créer une migration
alembic revision --autogenerate -m "description"
# Appliquer
alembic upgrade head
```

Note : le démarrage de l'app (`backend/main.py`) crée toujours le schéma via
`Base.metadata.create_all()` (dev rapide, pas de dépendance à un `alembic upgrade`
préalable) et patche ad hoc les colonnes ajoutées après coup sur les bases déjà
provisionnées. `alembic upgrade head` est la voie recommandée pour une base neuve gérée
en prod ; les deux mécanismes coexistent tant que l'app n'appelle pas elle-même
`alembic upgrade head` à son démarrage.

---

## Lancer les tests

```bash
cd backend
pytest tests/ -v
```

---

## Structure du projet

```
nexussecure/
├── backend/
│   ├── app/
│   │   ├── api/          # Endpoints REST
│   │   ├── auth/         # JWT + RBAC
│   │   ├── models/       # SQLAlchemy models
│   │   ├── schemas/      # Pydantic schemas
│   │   ├── services/     # Scanner, PDF, Vuln analyzer
│   │   ├── database/     # Engine + sessions
│   │   ├── logs/         # Fichiers de logs
│   │   └── utils/        # Logger
│   ├── tests/
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── templates/        # Jinja2 HTML
│   └── static/
│       ├── css/
│       └── js/
├── alembic/
├── docker-compose.yml
└── .env.example
```

---

## API REST — Référence

### Authentification

| Méthode | URL | Description |
|---------|-----|-------------|
| POST | `/api/auth/token` | Login → JWT token |

**Corps** (form-data) : `username`, `password`

**Réponse** :
```json
{ "access_token": "eyJ...", "token_type": "bearer" }
```

Tous les autres endpoints nécessitent le header :
```
Authorization: Bearer <token>
```

---

### Utilisateurs (`/api/users`)

| Méthode | URL | Rôle requis | Description |
|---------|-----|-------------|-------------|
| GET | `/api/users/me` | Tous | Profil courant |
| GET | `/api/users` | admin | Liste des utilisateurs |
| POST | `/api/users` | admin | Créer un utilisateur |
| PATCH | `/api/users/{id}` | admin | Modifier un utilisateur |
| DELETE | `/api/users/{id}` | admin | Supprimer un utilisateur |

**POST /api/users** :
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Secure@123!",
  "role": "analyst"
}
```

Rôles disponibles : `admin`, `analyst`, `client`

---

### Scans (`/api/scans`)

| Méthode | URL | Rôle requis | Description |
|---------|-----|-------------|-------------|
| GET | `/api/scans` | Tous | Liste des scans |
| POST | `/api/scans` | admin, analyst | Lancer un scan |
| GET | `/api/scans/{id}` | Tous | Détail d'un scan |
| DELETE | `/api/scans/{id}` | admin, analyst | Supprimer un scan |

**POST /api/scans** :
```json
{ "target": "192.168.1.0/24" }
```

Le scan s'exécute en **arrière-plan** (BackgroundTasks). Statuts : `pending → running → completed | failed`.

---

### Vulnérabilités (`/api/vulnerabilities`)

| Méthode | URL | Description |
|---------|-----|-------------|
| GET | `/api/vulnerabilities` | Liste (filtres: `scan_id`, `severity`) |
| GET | `/api/vulnerabilities/stats` | Comptage par sévérité |

Sévérités : `critical`, `high`, `medium`, `low`, `info`

---

### Rapports (`/api/reports`)

| Méthode | URL | Rôle requis | Description |
|---------|-----|-------------|-------------|
| GET | `/api/reports` | Tous | Liste des rapports |
| POST | `/api/reports/{scan_id}` | admin, analyst | Générer un PDF |
| GET | `/api/reports/{id}/download` | Tous | Télécharger le PDF |

---

### Dashboard (`/api/dashboard`)

| Méthode | URL | Description |
|---------|-----|-------------|
| GET | `/api/dashboard/stats` | KPI globaux + scans récents |

**Réponse** :
```json
{
  "total_scans": 12,
  "total_hosts": 47,
  "total_vulnerabilities": 83,
  "critical": 5,
  "high": 18,
  "recent_scans": [...]
}
```

---

## Sécurité applicative

- Mots de passe hashés avec **bcrypt** (passlib)
- Tokens **JWT** signés HS256, expiration configurable
- **RBAC** : admin / analyst / client avec vérification par dépendance FastAPI
- **Rate limiting** : 200 req/min par IP (SlowAPI)
- Validation stricte des entrées IP/CIDR via Pydantic `field_validator`
- Protection contre l'injection SQL via SQLAlchemy ORM (requêtes paramétrées)
- Logs horodatés de toutes les connexions et actions sensibles

---

## Compte admin initial

Au premier démarrage, si `FIRST_ADMIN_PASSWORD` n'est pas défini dans `.env`, un mot de passe
aléatoire est généré pour `admin@nexussecure.local` et **affiché une seule fois** dans les logs
(`app/logs/nexussecure.log` et stdout, niveau `WARNING`). Le compte a le flag
`must_change_password` actif : toutes les routes protégées renvoient `403` tant que le mot de
passe n'a pas été changé via `PATCH /api/users/me/password`.

---

## Diagramme simplifié des relations DB

```
User ──< Scan ──< Host ──< Port
                      └──< Vulnerability
         └── Report
Log
```

---

## Évolutions futures

- Intégration **OpenVAS** / CVE API (NVD)
- Module **Wireshark** (analyse de captures pcap)
- Intégration **Fail2Ban** (blocage automatique)
- **WebSocket** pour le suivi temps réel des scans
- Authentification **LDAP/AD**
- Export Excel des rapports
