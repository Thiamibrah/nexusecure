# CLAUDE.md — Guide pour les assistants IA travaillant sur NexusSecure

Ce fichier est un primer pour Claude (ou tout autre assistant de code IA) qui contribue à
ce dépôt. À lire avant toute modification.

## Ce qu'est cette application

**NexusSecure** est une plateforme interne d'audit et de sécurisation des réseaux
informatiques : lancer des scans réseau (nmap), classer les vulnérabilités trouvées par
sévérité, générer des rapports PDF, et suivre l'évolution du risque dans le temps. Trois
rôles utilisateurs :

1. **admin** — gestion des utilisateurs, vue globale sur tous les clients/scans.
2. **analyst** — lance les scans, analyse les vulnérabilités, commente, génère les rapports.
3. **client** — consulte en lecture seule les scans/rapports qui lui sont assignés (via `Scan.client_id`).

## Stack

- **Backend** : Python 3.12, FastAPI 0.111, SQLAlchemy 2.0, Alembic (configuré mais pas
  encore utilisé — voir "Dette connue"), JWT (`python-jose`), bcrypt
- **Scanner** : `python-nmap` (wrapper autour du binaire `nmap`)
- **Rapports** : ReportLab (génération PDF)
- **Frontend** : Bootstrap 5 + Chart.js + Jinja2 (server-rendered, pas de SPA)
- **DB** : SQLite en dev, PostgreSQL en prod (`DATABASE_URL`)
- **Rate limiting** : SlowAPI (voir `app/core/limiter.py`)
- **Tests** : pytest + `TestClient` (FastAPI/Starlette), voir `backend/tests/`

## Conventions critiques (ne pas enfreindre)

### Contrôle d'accès — le pattern à connaître par cœur

Il y a **deux mécanismes distincts, tous deux nécessaires** sur chaque nouvelle route :

1. **Rôle** — via les dépendances de `app/auth/dependencies.py` :
   `get_current_user` (authentifié, peu importe le rôle), `require_admin`,
   `require_analyst` (admin + analyst). Ne jamais écrire une vérification de rôle
   ad hoc inline — utiliser `require_roles(...)` si un nouveau combo est nécessaire.
2. **Propriété (scoping)** — un rôle valide ne suffit pas : un `analyst` ou un `client`
   doit être restreint aux scans qui lui appartiennent. Utiliser
   `allowed_scan_ids(db, current_user)` (dans `app/auth/dependencies.py`) — retourne
   `None` pour un admin (illimité) ou la liste des `scan_id` autorisés sinon. **Plusieurs
   IDOR ont déjà été trouvés et corrigés** (téléchargement de rapport, comparaison de
   scans, consultation/commentaire de scan par un analyste tiers — voir
   `SECURITY_FIXES.md`) parce que ce second mécanisme avait été oublié sur des routes qui
   vérifiaient bien le rôle mais pas la propriété. Avant d'ajouter une route qui prend un
   `scan_id`/`report_id`/`vuln_id` en paramètre, vérifier explicitement l'appartenance
   (au besoin en remontant une relation, ex. `vuln.host.scan_id`) — ne pas supposer que
   `require_analyst` suffit. `tests/test_reports.py`, `tests/test_dashboard.py` et
   `tests/test_vulnerabilities.py` couvrent ces cas croisés (client↔client,
   analyste↔analyste) — copier ce pattern pour toute nouvelle route scopée. Les fixtures
   `client_token`/`other_client_token`/`other_analyst_token` et les helpers
   `make_scan`/`make_host`/`make_vulnerability`/`make_report` (`tests/conftest.py`)
   existent pour ça.

### Mot de passe admin par défaut

Ne jamais réintroduire de mot de passe par défaut codé en dur. Le compte admin initial
est généré aléatoirement au démarrage si `FIRST_ADMIN_PASSWORD` n'est pas dans `.env`
(voir `main.py::_seed_admin`), avec le flag `User.must_change_password` qui bloque tout
accès (sauf changement de mot de passe) tant qu'il n'a pas été levé. Voir
`app/auth/dependencies.py::PASSWORD_CHANGE_EXEMPT_PATHS` pour la liste des routes
exemptées — toute nouvelle route que le flux "changer son mot de passe" doit pouvoir
atteindre doit y être ajoutée explicitement.

### Rate limiting

Le `Limiter` SlowAPI vit dans `app/core/limiter.py` (module séparé exprès, pour éviter un
import circulaire entre `main.py` et les routers `app/api/*`). Importer `limiter` depuis
là, jamais en créer une nouvelle instance. Pour limiter une route :
`@limiter.limit("N/minute")` juste après le décorateur de route, et la fonction doit
accepter un paramètre `request: Request` (exigé par SlowAPI). Dans les tests,
`limiter.enabled = False` est positionné une fois par session dans `conftest.py` — sinon
les fixtures qui appellent `/api/auth/token` plusieurs fois par run se prennent des `429`.

### Scanner nmap

Le champ `target` (`ScanCreate`) est validé par une regex stricte IP/CIDR
(`app/schemas/scan.py`) avant d'atteindre `python-nmap` — c'est ce qui empêche
l'injection de commande. **Ne jamais** construire une commande nmap avec de
l'input utilisateur non passé par ce validateur, et ne jamais rendre les `arguments`
nmap (actuellement une constante dans `services/scanner.py`) contrôlables par
l'utilisateur sans revue de sécurité.

### Base de données / migrations

`alembic.ini` vit à la racine du projet (à côté de `alembic/`) — toute commande Alembic
s'exécute depuis la racine, pas depuis `backend/` (voir README). Une première migration
existe (`alembic/versions/513f9c0215e8_initial_schema.py`), mais **l'app ne l'applique
pas automatiquement** : `main.py` continue de créer le schéma via
`Base.metadata.create_all()` au démarrage, pour rester utilisable sans étape manuelle en
dev. Si tu ajoutes/modifies une colonne sur un modèle existant : (1) génère une nouvelle
révision Alembic (`alembic revision --autogenerate -m "..."`, exécuté depuis la racine)
pour les déploiements gérés par Alembic, **et** (2) ajoute un patch ad hoc idempotent
dans `main.py` (voir `_migrate_users_table()` comme modèle) pour les bases existantes
créées via `create_all()` — `create_all()` ne fait *pas* d'`ALTER TABLE` sur une table
déjà présente, les deux mécanismes doivent donc être tenus à jour ensemble.

### Secrets

- `.env` n'est jamais commité ; `.env.example` ne doit contenir que des placeholders,
  jamais de vraie valeur ni de mot de passe par défaut fonctionnel.
- `SECRET_KEY` (JWT) doit être généré via `secrets.token_hex(32)`, jamais la valeur par
  défaut `"changeme"` de `app/config.py` en dehors du dev local.

### Révocation de token

Chaque JWT porte un `jti` unique (`app/auth/security.py::create_access_token`).
`POST /api/auth/logout` insère ce `jti` dans la table `revoked_tokens`
(`app/models/revoked_token.py`) ; `get_current_user` rejette (`401`) tout token dont le
`jti` y figure. `main.py::_purge_expired_revoked_tokens()` nettoie les entrées expirées
au démarrage — ne pas retirer cet appel, sinon la table grossit indéfiniment. La durée
"remember me" (7 jours, `security.py`) n'a pas été changée — un token non explicitement
révoqué reste valide jusqu'à expiration naturelle.

### Politique de mot de passe

Toute route qui fixe un mot de passe (création, self-service, reset admin) doit passer
par `app/auth/password_policy.py::password_policy_errors()` — ne pas réintroduire de
vérification `len(password) < 8` isolée. Voir les trois points d'appel existants
(`schemas/user.py`, `api/users.py::change_own_password`, `::admin_reset_password`) comme
modèle pour tout nouveau point d'entrée.

### En-têtes de sécurité / CSP

`main.py::add_security_headers` pose une CSP sur chaque réponse. Elle autorise
`'unsafe-inline'` pour scripts/styles parce que les templates Jinja2 en dépendent
massivement (pas de nonce) — **ne pas resserrer cette CSP sans vérifier chaque template**
listé dans le commentaire au-dessus de `_CSP`. Si un nouveau template charge une
ressource externe, ajouter son origine à la directive concernée plutôt que d'élargir en
`*`.

## Structure du projet

```text
backend/
  app/
    api/          # Routes REST (auth, users, scans, vulnerabilities, reports, dashboard, logs)
    auth/          # security.py (hash/JWT), dependencies.py (get_current_user, RBAC, scoping)
    core/          # limiter.py (instance SlowAPI partagée)
    models/        # SQLAlchemy (user, scan/host/port, vulnerability, report, log)
    schemas/       # Pydantic (validation d'entrée, ex. regex IP dans schemas/scan.py)
    services/      # scanner.py (nmap), pdf.py (ReportLab), vuln_analyzer.py, email.py
    database/      # engine + session
    utils/logger.py
  tests/           # pytest — auth, scans, users, reports, dashboard, vulnerabilities, vuln_analyzer
  main.py          # app FastAPI, lifespan (seed admin, migrations ad hoc), middlewares
frontend/
  templates/       # Jinja2
  static/{css,js}/
alembic/           # configuré, pas encore de migrations versionnées
docker-compose.yml # network_mode: host (requis pour la découverte nmap) — voir dette connue
```

## Dette de sécurité connue (non corrigée)

Voir `SECURITY_FIXES.md` pour le détail complet et l'historique (Critique, Élevée,
Moyenne, Faible et Info ont toutes été traitées à ce stade, ainsi que le bug annexe de
chargement de `.env`). Reste ouvert :

- JWT en `localStorage` reste exfiltrable par une XSS déjà exécutée dans la page (la CSP
  ajoutée réduit la surface d'attaque mais n'élimine pas ce vecteur — migration vers un
  cookie `httpOnly` non faite, voir "En-têtes de sécurité / CSP" ci-dessus).
- `network_mode: host` est conservé volontairement (nécessaire à la découverte d'hôtes
  nmap par ARP) — root a été retiré du conteneur, mais l'accès au réseau de l'hôte reste
  un compromis fonctionnel assumé, pas un bug.

Ne pas corriger ces points "en passant" au fil d'une tâche non liée sans le signaler
explicitement à l'utilisateur — ce sont des changements de comportement/sécurité qui
méritent leur propre revue.

## Dev local

```bash
cd backend
python -m venv venv && source venv/Scripts/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example ../.env   # puis éditer SECRET_KEY, FIRST_ADMIN_PASSWORD (optionnel)
uvicorn main:app --reload
```

```bash
cd backend
pytest tests/ -v
```

Le compte admin initial et son mot de passe (si généré) apparaissent dans les logs au
premier démarrage (`app/logs/nexussecure.log`, niveau `WARNING`) — pas ailleurs.

## Don'ts (règles dures)

- Ne jamais réintroduire un mot de passe par défaut codé en dur, ni le documenter en
  clair dans le README.
- Ne jamais ajouter de route prenant un `scan_id`/`report_id`/`vuln_id` sans passer par
  `allowed_scan_ids` (ou équivalent) en plus de la vérification de rôle.
- Ne jamais construire une commande nmap à partir d'input utilisateur non validé par le
  schéma Pydantic existant.
- Ne jamais committer `.env` ou une vraie valeur de `SECRET_KEY`/mot de passe dans
  `.env.example`, `docker-compose.yml` ou ailleurs.
- Ne pas désactiver le rate limiting en dehors des tests sans concertation.
- Ne pas contourner `password_policy_errors()` avec une vérification de longueur isolée.
- Ne pas retirer `_purge_expired_revoked_tokens()` du démarrage sans mettre autre chose
  en place pour éviter que `revoked_tokens` grossisse indéfiniment.

---

Petites PR ciblées de préférence. Pour toute modification touchant l'auth, le RBAC, ou le
scanner, demander confirmation avant un refactor large — c'est la zone la plus sensible
du projet.
