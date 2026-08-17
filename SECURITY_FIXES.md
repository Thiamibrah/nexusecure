# Corrections de sécurité — NexusSecure

Journal des correctifs appliqués suite à un audit de code (2026-08-17). Chaque entrée
référence le finding original, ce qui a été changé, et comment c'est vérifié.

Findings identifiés lors de l'audit initial (numérotation conservée pour traçabilité) :
Critique #1, #2 · Élevée #3, #4 · Moyenne #5-#9 · Faible #10-#11 · Info #12-#15.
**#1 à #9 (Critique + Élevée + Moyenne) sont corrigés.** Faible et Info restent listés en
fin de document sous "Findings non corrigés" pour rester traçable.

---

## Critique #1 — Compte admin par défaut sans rotation forcée

**Avant** : `Admin@1234!` était codé en dur comme valeur par défaut dans `Settings`
(`app/config.py`), documenté en clair dans le README, et rien ne forçait un changement
au premier login.

**Après** :
- `app/config.py` — `FIRST_ADMIN_PASSWORD` n'a plus de valeur par défaut (`None`).
- `app/models/user.py` — nouvelle colonne `must_change_password: bool`.
- `backend/main.py::_seed_admin()` — si `FIRST_ADMIN_PASSWORD` n'est pas défini dans
  `.env`, un mot de passe aléatoire (`secrets.token_urlsafe(12)`) est généré et **loggé
  une seule fois** (niveau `WARNING`, dans `app/logs/nexussecure.log` et stdout). Le
  compte est créé avec `must_change_password=True`.
- `backend/main.py::_flag_known_default_passwords()` — remédiation rétroactive : au
  démarrage, tout compte existant dont le hash correspond encore à l'ancien mot de passe
  documenté (`Admin@1234!`) est automatiquement flagué `must_change_password=True`. Cette
  passe est un correctif ponctuel pour les instances déjà provisionnées — elle fait un
  `bcrypt.checkpw` par utilisateur à chaque démarrage, donc **à retirer une fois toutes
  les instances migrées** (voir TODO en bas de fichier).
- `backend/main.py::_migrate_users_table()` — ajoute la colonne `must_change_password`
  aux bases SQLite/Postgres existantes (aucune migration Alembic n'existait — voir
  finding Info #12, toujours ouvert).
- `app/auth/dependencies.py::get_current_user()` — point d'enforcement central : si
  `must_change_password` est actif, toute route protégée renvoie `403` **sauf**
  `GET /api/users/me`, `PATCH /api/users/me/password`, `POST /api/auth/logout`
  (liste `PASSWORD_CHANGE_EXEMPT_PATHS`).
- `app/api/users.py::change_own_password()` — repasse le flag à `False` au changement
  volontaire.
- `app/api/users.py::admin_reset_password()` — force le flag à `True` quand un admin
  réinitialise le mot de passe d'un autre utilisateur (celui-ci doit le changer à son
  tour).
- `README.md`, `.env.example` — retrait du mot de passe en clair.

**Vérifié** : suite de tests (`test_auth.py`, `test_users.py`) passe inchangée — le
compte de test créé par `conftest.py` n'a pas `must_change_password` actif (défaut
`False`), donc pas de régression.

---

## Critique #2 — IDOR sur le téléchargement de rapports

**Avant** : `GET /api/reports/{report_id}/download` (`app/api/reports.py`) ne vérifiait
que l'authentification, pas la propriété du rapport — un client pouvait télécharger le
PDF d'un autre client en incrémentant l'ID.

**Après** : pour le rôle `client`, on vérifie que `report.scan_id` appartient bien à un
scan dont `client_id == current_user.id` (même logique que `list_reports`, qui était
déjà correcte). `404` si non — pas de fuite d'information sur l'existence du rapport.

---

## Élevée #3 — Rate limiting déclaré mais jamais actif

**Avant** : `Limiter` était instancié dans `main.py` et l'exception handler enregistré,
mais aucun décorateur `@limiter.limit(...)` ni `SlowAPIMiddleware` n'était branché —
l'objet ne filtrait aucune requête. Combiné au finding #1, le login était soumis à un
brute force illimité.

**Après** :
- Nouveau module `app/core/limiter.py` — instance `Limiter` partagée, extraite de
  `main.py` dans son propre fichier pour éviter un import circulaire entre `main.py` et
  les routers de `app/api/*` qui doivent aussi l'utiliser.
- `main.py` — ajout de `app.add_middleware(SlowAPIMiddleware)` (limite globale par
  défaut : 200/min/IP, déjà déclarée).
- `POST /api/auth/token` (`app/api/auth.py`) — `@limiter.limit("5/minute")`.
- `POST /api/scans` (`app/api/scans.py`) — `@limiter.limit("20/minute")` (les scans nmap
  sont coûteux ; limite plus permissive que le login car réservée aux rôles
  admin/analyst).

**Vérifié** : première exécution de la suite réduite (`test_auth.py` + `test_users.py` +
`test_scans.py`, sans le test lent qui scanne réellement `127.0.0.1`) a immédiatement
cassé 9 tests avec des `429 Too Many Requests` — les fixtures `admin_token`/
`analyst_token` de `tests/conftest.py` appellent `/api/auth/token` bien plus souvent
qu'un client réel ne le ferait en une minute. Corrigé en désactivant le limiter pour
toute la session de tests (`tests/conftest.py::setup_db` : `limiter.enabled = False`,
en important l'instance partagée de `app/core/limiter.py`) — le rate limiting est une
préoccupation de prod, pas quelque chose que cette suite cherche à valider. Après ce
correctif, la suite complète repasse à 16/18 (mêmes 2 échecs préexistants et non liés
dans `test_vuln_analyzer.py`, voir plus bas).

---

## Élevée #4 — IDOR sur `GET /api/dashboard/compare`

**Avant** : aucun filtrage de propriété sur `scan_before`/`scan_after` fournis en query
params — un client ou analyste pouvait comparer les scans d'un tiers.

**Après** : réutilise le pattern déjà présent dans `app/api/vulnerabilities.py`
(`_allowed_scan_ids`), désormais mutualisé dans `app/auth/dependencies.py` sous le nom
`allowed_scan_ids(db, user)` — importé par `vulnerabilities.py` (qui a perdu sa copie
locale) et par `dashboard.py`. `compare_scans` renvoie `404` si l'un des deux IDs sort du
périmètre de l'utilisateur.

---

## Moyenne #5 — RBAC incohérent pour le rôle `analyst`

**Avant** : `list_scans` restreignait bien un analyste à ses propres scans
(`Scan.user_id == current_user.id`), mais `get_scan` (`scans.py`) ne vérifiait la
propriété que pour le rôle `client`. `add_comment` (`vulnerabilities.py`) ne vérifiait
que le rôle (`require_analyst`), jamais l'appartenance de la vulnérabilité à un scan de
l'appelant.

**Après** :
- `scans.py::get_scan` — utilise désormais `allowed_scan_ids(db, current_user)` :
  `403` si `scan_id` n'est pas dans le périmètre (admin non restreint).
- `vulnerabilities.py::add_comment` — récupère le `scan_id` via `vuln.host.scan_id` et le
  vérifie contre `allowed_scan_ids` ; `404` si hors périmètre (pas de fuite d'existence).

---

## Moyenne #6 — Pas de révocation de token

**Avant** : `POST /api/auth/logout` se contentait d'écrire un log ; le JWT restait valide
jusqu'à expiration naturelle (jusqu'à 7 jours en mode "remember me").

**Après** :
- Nouveau modèle `app/models/revoked_token.py::RevokedToken` (`jti`, `revoked_at`,
  `expires_at`), enregistré dans `app/models/__init__.py` pour que `create_all()` le crée.
- `app/auth/security.py::create_access_token` — ajoute un `jti` (UUID) unique à chaque
  token émis.
- `app/auth/dependencies.py::get_current_user` — vérifie le `jti` du token contre
  `RevokedToken` à chaque requête ; `401 "Token revoked"` si trouvé.
- `app/api/auth.py::logout` — décode le token courant et insère son `jti`/`exp` dans
  `RevokedToken`, donc les autres requêtes utilisant ce même token échouent immédiatement
  après un logout, au lieu d'attendre l'expiration naturelle.
- `backend/main.py::_purge_expired_revoked_tokens()` — purge au démarrage les entrées
  déjà expirées, pour que la table ne grossisse pas indéfiniment (une entrée par logout).

**Limite connue** : la durée "remember me" (7 jours) n'a pas été réduite — seule la
révocation explicite au logout a été ajoutée. Un token volé avant tout logout reste
valide jusqu'à expiration naturelle, comme avant.

---

## Moyenne #7 — Politique de mot de passe faible

**Avant** : seule contrainte = 8 caractères minimum, dupliquée entre
`schemas/user.py` (validateur Pydantic) et `api/users.py` (deux vérifications inline
`len(...) < 8`), sans exigence de complexité.

**Après** : nouveau module `app/auth/password_policy.py::password_policy_errors()` —
exige minuscule, majuscule, chiffre, caractère spécial en plus des 8 caractères. Appliqué
aux trois points d'entrée qui fixent un mot de passe : `UserCreate` (validateur
Pydantic), `change_own_password`, `admin_reset_password`. Les mots de passe de test
existants (`Admin@1234!`, `Analyst@123!`, `Client@123!`, `Pass@5678!`) respectent déjà
cette politique — pas de régression.

---

## Moyenne #8 — JWT en `localStorage`, pas de CSP

**Avant** : aucun en-tête de sécurité ; le token JWT (lisible par tout script exécuté
dans la page) n'avait aucune CSP pour limiter l'impact d'une XSS.

**Après** : middleware `add_security_headers` dans `main.py` ajoutant sur chaque réponse :
`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: strict-origin-when-cross-origin`.

**Limite assumée et documentée dans le code** : la CSP autorise `'unsafe-inline'` pour
`script-src`/`style-src` car les templates Jinja2 (`compare.html`, `dashboard.html`,
`login.html`, `logs.html`, `profile.html`, `reports.html`, `scans.html`, `users.html`,
`vulnerabilities.html`) contiennent tous des blocs `<script>` inline et des attributs
`style=""`, sans nonce. Une CSP stricte sans `unsafe-inline` casserait l'intégralité du
front. Ce correctif réduit quand même la surface réelle : bloque le chargement de
scripts/frames depuis des origines tierces arbitraires (seul `cdn.jsdelivr.net` est
autorisé), le clickjacking (`frame-ancestors 'none'`), et le MIME-sniffing. **Ne protège
pas** contre l'exfiltration du token localStorage par une XSS déjà exécutée dans la page —
la vraie remédiation (migration vers un cookie `httpOnly`/`Secure`/`SameSite=strict`, ou
un système de nonce par requête pour les scripts inline) n'a pas été faite ici : c'est un
changement d'architecture plus large (touche le stockage du token côté front dans
plusieurs fichiers JS, le flux de login, et potentiellement CORS) qui mérite sa propre
revue plutôt que d'être fait au fil de cette passe.

---

## Moyenne #9 — Dépendance CSRF morte

**Avant** : `starlette-csrf==3.0.0` listée dans `requirements.txt`, jamais importée ni
utilisée dans le code.

**Après** : dépendance retirée. L'API est protégée par des Bearer tokens (pas de cookies
de session envoyés automatiquement par le navigateur), donc une protection CSRF
classique n'apporterait pas de protection réelle dans ce modèle d'authentification —
inutile de la brancher artificiellement. À réintroduire uniquement si l'auth migre un
jour vers des cookies (voir limite du #8 ci-dessus).

---

## Faible #10 — Conteneur Docker root + `network_mode: host`

**Avant** : `backend/Dockerfile` ne déclarait aucun `USER` — le process tournait en root
dans le conteneur, cumulé à `network_mode: host` (accès direct au namespace réseau de
l'hôte).

**Après** :
- `Dockerfile` — création d'un utilisateur non-root (`appuser`, uid 1000), `chown` de
  `/app`, `USER appuser` avant le `CMD`.
- `docker-compose.yml` — `cap_add: [NET_RAW, NET_ADMIN]` sur le service `api`, pour que
  nmap conserve ses capacités de scan SYN/découverte d'hôte sans avoir besoin de root.

**Ce qui n'a volontairement pas changé** : `network_mode: host` est conservé. Le
commentaire d'origine ("required for nmap host discovery") est réel — la découverte
d'hôtes par ARP nécessite un accès L2 direct, que le mode réseau bridge par défaut de
Docker n'offre pas. Le retirer casserait la fonctionnalité de scan sur un LAN local,
donc ce n'est pas un simple oubli de sécurité mais un compromis fonctionnel assumé. Le
risque résiduel (accès au réseau de l'hôte en cas de compromission applicative) est donc
partiellement atténué (plus de root) mais pas éliminé — à documenter pour l'équipe ops
si le déploiement change de contexte réseau.

---

## Faible #11 — Identifiants Postgres en clair dans `docker-compose.yml` versionné

**Avant** : `POSTGRES_PASSWORD: nexus_secret` codé en dur, réutilisé tel quel dans
`DATABASE_URL`, port `5432` publié sur toutes les interfaces.

**Après** :
- `docker-compose.yml` — `POSTGRES_DB`/`POSTGRES_USER`/`POSTGRES_PASSWORD` lus depuis
  l'environnement (`.env`, via l'interpolation native de Docker Compose) ;
  `POSTGRES_PASSWORD` utilise la syntaxe `${VAR:?message}` — **Compose refuse de démarrer
  si elle n'est pas définie**, donc pas de mot de passe faible par défaut possible.
  `DATABASE_URL` du service `api` est reconstruite à partir des mêmes variables.
- Port Postgres publié en `127.0.0.1:5432:5432` au lieu de `5432:5432` — plus accessible
  depuis l'extérieur de la machine hôte par défaut.
- `.env.example` — ajout des trois variables avec un placeholder explicite à remplacer.

**Vérifié** : `docker-compose.yml` reste un YAML valide (`yaml.safe_load` OK). Pas de
test automatisé pour le déploiement Docker lui-même dans ce repo — à valider avec un
`docker compose up` manuel si besoin avant un déploiement réel.

---

## Info #12 — Pas de vraie migration Alembic

**Avant** : `alembic/versions/` était vide. En creusant pour générer une première
migration, découverte d'un **bug de configuration séparé** : `alembic.ini` vivait dans
`backend/` alors que le dossier `alembic/` qu'il référence (`script_location = alembic`)
est à la racine du projet — la commande documentée dans le README
(`cd backend && alembic revision --autogenerate`) échouait donc silencieusement/avec une
erreur de chemin, ce qui explique probablement pourquoi aucune migration n'avait jamais
été générée.

**Après** :
- `alembic.ini` déplacé de `backend/alembic.ini` vers `alembic.ini` (racine du projet),
  à côté du dossier `alembic/` qu'il configure — layout standard Alembic.
- `alembic/env.py` — le `sys.path.insert` pointait vers la racine du projet (où `app`
  n'existe pas) ; corrigé pour pointer vers `backend/` (où vit réellement le package
  `app`), afin que les commandes fonctionnent quel que soit le CWD d'où `alembic` est
  invoqué.
- `README.md` — section "Migrations Alembic" mise à jour : les commandes s'exécutent
  désormais depuis la racine du dépôt.
- Génération d'une vraie première migration (`alembic/versions/513f9c0215e8_initial_schema.py`)
  via autogenerate contre une base vide, capturant tout le schéma actuel (y compris
  `must_change_password` et `revoked_tokens` ajoutés dans cette même passe de
  correctifs).

**Vérifié** : `alembic upgrade head` puis `alembic downgrade base` testés sur une base
sqlite temporaire — round-trip propre, sans erreur.

**Ce qui n'a pas changé** : l'app continue de créer son schéma via
`Base.metadata.create_all()` au démarrage (`main.py`), pas via `alembic upgrade head`
automatique — les deux mécanismes coexistent (voir README). La migration générée sert de
point de départ pour un déploiement qui choisirait de gérer son schéma uniquement via
Alembic (ex. Postgres en prod).

---

## Info #13 — Regex IP sans bornes 0-255

**Avant** : `^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$` acceptait des octets à 3 chiffres sans
borne (`999.999.999.999` passait la validation) et un préfixe CIDR sans borne (`/99`).

**Après** (`schemas/scan.py`) : chaque octet est borné 0-255
(`25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d`), le préfixe CIDR est borné 0-32. Sans impact sécurité
en soi (le charset restreint empêchait déjà toute injection), mais évite de transmettre
une entrée invalide à `python-nmap`.

---

## Bonus — Chargement de `.env` dépendant du CWD

**Découvert** en creusant le chargement de `.env` pour le fix Alembic (Info #12) :
`Settings.model_config = SettingsConfigDict(env_file=".env", ...)` (`app/config.py`)
utilisait un chemin **relatif**, résolu par pydantic-settings par rapport au CWD au
moment de l'instanciation. Le vrai fichier `.env` vit à la racine du projet
(`C:\nexussecure\.env`), mais les instructions de dev local du README font tourner
`uvicorn` depuis `backend/` (`cd backend && uvicorn main:app --reload`) — CWD =
`backend/`, où il n'existe **pas** de `.env` (confirmé). Conséquence : en dev local (hors
Docker), l'app ne chargeait jamais le vrai `.env` et retombait silencieusement sur les
valeurs par défaut de `Settings` (`SECRET_KEY="changeme"` notamment). En Docker ce
n'était pas un problème (Compose injecte les variables directement via `env_file:`,
indépendamment de la logique de chargement de pydantic-settings) — c'est pour ça que ça
n'avait pas été remarqué.

**Corrigé** (`app/config.py`) : `env_file` est désormais un `Path` absolu ancré sur
l'emplacement du fichier lui-même (`Path(__file__).resolve().parent.parent.parent / ".env"`
— `config.py` → `app/` → `backend/` → racine du projet), donc indépendant du CWD depuis
lequel `uvicorn`/`pytest`/`alembic` est invoqué.

**Vérifié** : lancé depuis `backend/` (le cas qui échouait avant), `settings.SECRET_KEY`
n'est plus la valeur par défaut `"changeme"` et `FIRST_ADMIN_PASSWORD` est bien chargé
(valeurs non affichées, juste vérifié qu'elles diffèrent des défauts / ne sont pas
`None`) — le `.env` racine est maintenant réellement pris en compte en dev local.

---

## Couverture de tests ajoutée pour les correctifs IDOR/RBAC

Les correctifs #2, #4 et #5 (téléchargement de rapport, comparaison de scans,
commentaire de vulnérabilité) n'étaient couverts par aucun test avant cette passe —
seule une relecture manuelle du code garantissait qu'ils fonctionnaient. Ajouté :

- `tests/test_reports.py` — téléchargement refusé entre clients (404), autorisé pour le
  propriétaire (200, avec un vrai fichier PDF via `tmp_path`), comportement volontairement
  non restreint pour un analyste (pour figer ce choix de design), scoping de `list_reports`.
- `tests/test_dashboard.py` — `compare_scans` refusé si l'un des deux scans (ou les deux)
  sort du périmètre, pour un `client` et pour un `analyst` (y compris cas croisé
  analyste↔analyste), autorisé pour le propriétaire, non restreint pour un admin.
- `tests/test_vulnerabilities.py` — `add_comment` refusé pour le rôle `client` (403),
  refusé entre analystes sur un scan qui n'est pas le leur (404), autorisé sur son propre
  scan et pour un admin, scoping de `list_vulnerabilities` pour un client.
- `tests/conftest.py` — nouvelles fixtures `client_token`, `other_client_token`,
  `other_analyst_token`, et helpers `user_id`, `make_scan`, `make_host`,
  `make_vulnerability`, `make_report` pour construire rapidement les chaînes
  scan→host→vulnérabilité/rapport nécessaires à ces tests.

**Vérifié** : 18/18 nouveaux tests passent seuls ; suite complète 34/36 (mêmes 2 échecs
préexistants et sans lien dans `test_vuln_analyzer.py`), aucune régression.

---

## Bonus — Bug fonctionnel `analyze_host` (2 tests `test_vuln_analyzer.py`)

Hors périmètre sécurité, mais traîné depuis le début de cette session : `test_telnet_is_critical`
et `test_http_is_medium` échouaient.

**Cause** (`app/services/vuln_analyzer.py::analyze_host`) : la fonction ré-interrogeait la
base (`db.query(Port).filter(Port.host_id == host.id).all()`) au lieu d'utiliser
`host.ports`, déjà chargé/disponible sur l'objet passé en paramètre. En prod
(`services/scanner.py`), ça fonctionnait par accident : `db.flush()` juste avant l'appel
rend les ports fraîchement insérés visibles à une requête dans la même transaction, donc
les deux approches renvoyaient le même résultat. Mais ça crée un couplage inutile à une
`Session` vivante (requête DB redondante à chaque appel) et rend la fonction impossible à
tester unitairement avec un `Host` mocké — exactement ce que faisaient ces deux tests, qui
peuplaient `host.ports` sur un `MagicMock` sans configurer `db.query(...)`, laissant
`analyze_host` itérer sur une liste vide côté mock.

**Corrigé** : `analyze_host` itère directement sur `host.ports`, suppression de la requête
`db.query(Port)` redondante et de l'import local devenu inutile.

**Vérifié** : suite complète **36/36** — les 2 tests visés passent, aucune régression.

## Bonus — CI GitHub Actions

Ajout de `.github/workflows/tests.yml` : lance `pytest tests/ -v` sur chaque push,
sur `ubuntu-latest`, Python 3.12. Installe `nmap` via `apt` (nécessaire pour
`test_create_scan_valid`, qui lance un vrai scan sur `127.0.0.1` via `python-nmap`) avant
les dépendances Python. Pas de secrets requis — `Settings` retombe sur ses valeurs par
défaut en l'absence de `.env` (aucun test ne dépend d'un vrai `SECRET_KEY`/DB externe).

**Non testé en conditions réelles** : ce projet n'est pas encore un dépôt git initialisé
(`git status` renvoie "not a git repository"), donc ce workflow n'a pas pu être vérifié
par un vrai run GitHub — seule la structure YAML a été validée localement.

## TODO de suivi

- Une fois toutes les instances de prod migrées vers ce correctif, retirer
  `_flag_known_default_passwords()` de `main.py` (coût bcrypt par utilisateur à chaque
  démarrage, utile seulement en transition).
