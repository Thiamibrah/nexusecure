# Audit UI/UX — NexusSecure

Analyse de l'interface (design, UX, fonctionnalités, plan d'amélioration), réalisée par
relecture complète des templates/CSS/JS croisée avec le backend, puis vérification en
direct dans le navigateur pour les points marqués **vérifié**. Version complète et
illustrée disponible en artifact ; ce fichier est la version de référence versionnée avec
le code.

Suivi des phases : voir `SECURITY_FIXES.md` pour l'historique de sécurité — ce document
couvre le design/UX, un chantier séparé.

---

## 1. Analyse de l'interface actuelle

**Design général** — thème sombre "cyber" cohérent (fonds bleu-nuit/anthracite, accent
vert), porté par `frontend/static/css/nexussecure.css` et une trentaine de classes
réutilisées partout (`.card-dark`, `.kpi-card`, `.badge-{sévérité}`). Le système existe
déjà ; ce qui manque est la discipline (valeurs répétées en dur plutôt que déclarées une
fois).

**Couleurs** — palette cohérente, échelle de sévérité identique entre badges CSS et
graphiques Chart.js. Point d'attention : le vert d'accent sert à la fois pour "action
positive" et pour "statut sécurisé" — deux sens sur la même teinte, surtout visible sur
le dashboard.

**Typographie** — une seule famille système (`Segoe UI`), raisonnable, mais pas d'échelle
de tailles déclarée : les titres de carte varient légèrement d'une page à l'autre en
inline sans intention apparente. Les libellés de tableau (`.table-dark th`) sont le seul
endroit avec une vraie hiérarchie typographique systématique.

**Navigation** — trois sidebars par rôle + dashboard à trois vues, pilotées par le rôle
décodé du JWT côté client (déjà en grande partie corrigé cette session : repli de
sidebar, lien du logo). Ordre logique (workflow puis administration) mais sans
séparateur visuel entre les deux groupes.

**Disposition des composants** — grille Bootstrap régulière (formulaire à gauche, liste à
droite ; KPI en haut, détail en dessous). Prévisible dans le bon sens.

**Boutons, formulaires, tableaux, cartes** :
- Boutons : un seul bouton plein par page (`.btn-accent`), le reste en
  `btn-outline-*` colorés par intention — cohérent.
- Formulaires : validation HTML5 basique + un bloc d'erreur unique. Le champ mot de
  passe de `users.html` affiche encore *"min 8 car."* alors que la politique backend
  (ajoutée cette session) exige aussi majuscule/minuscule/chiffre/spécial — indice
  désynchronisé **vérifié**.
- Tableaux : cohérents visuellement, mais seul le tableau admin du Dashboard est
  enveloppé dans `.table-responsive` **vérifié** — Scans, Utilisateurs, Rapports et
  Vulnérabilités (8 colonnes) n'ont pas ce conteneur.
- Cartes : un seul style (`.card-dark`) réutilisé partout — vraie force.

**Cohérence entre pages** — bonne dans l'ensemble. Deux incohérences concrètes :
- Le score de risque s'affiche sur deux échelles différentes selon la page : Dashboard
  correct (`/100`), mais `reports.html` et `compare.html` affichent `/10` alors que la
  donnée API est bien 0-100 **vérifié dans `pdf.py`/`dashboard.py`**.
- Confirmations destructives via `confirm()`/`prompt()` natifs du navigateur — seul
  endroit hors thème de toute l'appli.

**UX** — points forts : les trois dashboards parlent le langage de chaque rôle (le
client voit un "score de sécurité" et des "priorités", pas des tableaux bruts). Manques :
aucun état de chargement, aucune pagination/tri/recherche (sauf filtre scan+sévérité sur
Vulnérabilités), et le flux "changement de mot de passe obligatoire" côté backend
(`must_change_password`) n'a aucune traduction côté front.

**Responsive** — mécanique de base fonctionnelle (sidebar en tiroir < 768px, testée en
direct). Les tableaux non enveloppés restent le vrai point faible, surtout
Vulnérabilités.

---

## 2. Bilan

**Points forts à préserver**
- Système de couleurs/badges de sévérité cohérent, y compris dans les graphiques.
- Dashboards adaptés à chaque rôle.
- Un seul style de carte, pas de dérive page par page.
- Navigation par rôle bien ordonnée.
- Filtre scan + sévérité sur Vulnérabilités — à généraliser plutôt qu'à réinventer.

**Points à corriger**
- Score de risque sur la mauvaise échelle (Rapports, Comparaison).
- Flux "mot de passe à changer" invisible côté front.
- `alert()`/`confirm()`/`prompt()` natifs pour les actions destructives.
- Aucun état de chargement ni distinction chargement/vide.
- Tableaux sans pagination/tri/recherche au-delà de Vulnérabilités.
- Tableaux sans `.table-responsive` hors dashboard admin.

---

## 3. Proposition de design

Garder la palette et l'identité sombre actuelles (cohérentes, adaptées au sujet) et les
faire évoluer en système documenté plutôt que de les remplacer :
- Consolider les tokens (`--text-fg`, `--text-muted`… déjà ajoutés cette session) et
  ajouter une couleur "statut sécurisé" distincte du vert d'action.
- Formaliser une échelle typographique à 5 paliers (page title / card title / body /
  label / caption) et une échelle d'espacement en base 4.
- Construire tout nouveau composant (toast, skeleton, état vide) avec les tokens
  existants, jamais une palette parallèle.

---

## 4. Fonctionnalités proposées

### Priorité élevée
1. **Flux de changement de mot de passe obligatoire** — `must_change_password` existe
   côté backend, aucune traduction front. Utilité : éviter qu'un utilisateur atterrisse
   sur un dashboard cassé silencieusement (403 partout). Utilisateurs : tout compte
   fraîchement seedé/réinitialisé. Fonctionnement : lire `must_change_password` depuis
   `/api/users/me`, rediriger vers `/profile` avec bandeau non fermable. Emplacement :
   `nexussecure.js` (garde global) + `profile.html`.
2. **Recherche/tri/pagination sur les tableaux** — Scans, Utilisateurs, Rapports.
   Utilité : usabilité à l'échelle. Utilisateurs : analystes/admins. Fonctionnement :
   filtre côté client sur les données déjà chargées. Emplacement : en-tête de chaque
   tableau.
3. **Toasts + modales de confirmation** — remplacer `alert`/`confirm`/`prompt` natifs.
   Utilité : cohérence visuelle sur les actions les plus sensibles. Utilisateurs : tous,
   admins en particulier. Fonctionnement : `toast()`/`confirmModal()` partagés dans
   `nexussecure.js`. Emplacement : toasts en haut à droite, modale Bootstrap réutilisée.
4. **Correction de l'échelle du score de risque** — `/10` → `/100` sur `reports.html` et
   `compare.html`. Bug de cohérence pure, priorité élevée car mine la confiance dans les
   chiffres affichés.

### Priorité moyenne
5. **Centre de notifications global (topbar)** — le panneau d'alertes existe déjà mais
   seulement sur le Dashboard. Réutiliser `/api/dashboard/alerts` depuis `base.html`.
6. **Badge "nouveaux rapports" sur la sidebar** — `/api/reports/new-count` existe côté
   backend, jamais appelé côté front **vérifié**.
7. **Export CSV des tableaux** — aligné avec la vision déjà déclarée au README ("Export
   Excel des rapports"). Génération côté client à partir des données déjà chargées.
8. **Filtres cohérents sur Scans et Rapports** — étendre le pattern déjà présent sur
   Vulnérabilités.

### Bonus
9. **Historique du score par cible** — graphique ligne (Chart.js) sur la série de
   rapports d'une cible, sans rien ajouter au modèle de données.
10. **Mode clair** — les tokens CSS déjà nommés rendent un double thème atteignable sans
    réécrire les templates.
11. **Indicateur de dernière mise à jour** — sur Scans/Logs, qui se rafraîchissent en
    silence toutes les 10-15s.

---

## 5. Améliorations visuelles par composant

| Composant | Constat / action |
|---|---|
| Dashboard | Structure solide. Ajouter skeleton animé sur KPI pendant le chargement ; distinguer couleur d'action et couleur de statut sécurisé. |
| Sidebar / Navbar | Repli, logo, couleurs déjà corrigés cette session. Reste : séparateur visuel entre bloc workflow et bloc administration. |
| Cards | Style unique, rien à changer structurellement. Formaliser l'échelle typographique des titres. |
| Tables | `.table-responsive` manquant sur 4/5 tableaux ; tri + recherche à ajouter ; état vide explicite au lieu d'un tableau simplement vide. |
| Formulaires | Synchroniser les indices de mot de passe avec la vraie politique backend ; validation par champ plutôt qu'un bloc d'erreur unique. |
| Modales | Pattern Bootstrap existant propre — le réutiliser pour les confirmations destructives. |
| Notifications | Voir fonctionnalité toasts — actuellement des `.alert` statiques par page, sans auto-disparition. |
| États de chargement | Absents partout sauf Dashboard (`—`). Composant skeleton réutilisable à standardiser. |
| Messages d'erreur/succès | Contenu déjà bon (ex. extraction des erreurs Pydantic multiples). Forme à aligner sur le futur système de toasts. |
| Icônes | Bootstrap Icons utilisées de façon cohérente et sémantique — rien à changer. |
| Animations/transitions | Peu présentes, cohérent avec un outil "sérieux". Ne pas en ajouter pour le principe ; respecter `prefers-reduced-motion`. |

---

## 6. Plan d'amélioration

| Phase | Contenu | Statut |
|---|---|---|
| **Phase 1** | Corrections sans risque : échelle du score de risque, indice mot de passe synchronisé, séparateur sidebar admin | **Terminée** |
| **Phase 2** | Flux critique manquant : câblage frontend de `must_change_password` | **Terminée** |
| **Phase 3** | Système de composants : toasts, modales de confirmation, skeletons, états vides, `.table-responsive` partout | **Terminée** |
| **Phase 4** | Recherche/tri/pagination, centre de notifications, badge rapports, export CSV, filtre statut Scans | **Terminée** |
| **Phase 5** | Bonus — historique de score par cible, mode clair, indicateur de dernière mise à jour | **Terminée** |
| Phase 2 | Flux critique manquant : câblage frontend de `must_change_password` | À venir |
| Phase 3 | Système de composants : toasts, modales de confirmation, skeletons, états vides, `.table-responsive` partout | À venir |
| Phase 4 | Fonctionnalités à forte valeur : recherche/tri/pagination, centre de notifications, badge rapports, export CSV | À venir |
| Phase 5 | Bonus : historique par cible, mode clair, indicateur de rafraîchissement | À venir |

---

## Journal des correctifs Phase 1

### Échelle du score de risque (`/10` → `/100`)

**Avant** : `reports.html` et `compare.html` affichaient `${score} / 10` alors que
`Report.risk_score`/`_scan_summary` renvoient une valeur 0-100 (`pdf.py::_risk_score`,
`dashboard.py::_scan_summary`) — le chiffre affiché était dix fois trop petit.

**Après** :
- `reports.html` — label corrigé en `/ 100`.
- `compare.html` — label corrigé en `/ 100`.
- **Bug additionnel trouvé en creusant** : la couleur du score dans `reports.html`
  utilisait des seuils calibrés pour une échelle 0-10 (`score >= 7` → rouge,
  `>= 4` → orange) alors que `score` a toujours été 0-100 — en pratique, presque tout
  score non nul (dès 7/100) s'affichait en rouge quelle que soit la vraie sévérité.
  Corrigé avec des seuils alignés sur `pdf.py::_risk_label` (0-40 vert, 41-60 orange,
  61-100 rouge).

**Vérifié** : connecté en direct, page Rapports — 4 rapports avec des scores réels
(0, 5.5, 6.5, 6.5 sur 100) affichent maintenant `/100` et la couleur verte attendue
(au lieu du rouge qu'ils affichaient avant, à tort). Page Comparaison — `0 / 100` et
`19.3 / 100` corrects sur un vrai diff avant/après.

### Indices de mot de passe désynchronisés de la politique backend

**Avant** : `users.html` affichait *"Mot de passe (min 8 car.)"*, `profile.html` et le
`prompt()` de réinitialisation admin ne mentionnaient que la longueur — alors que
`app/auth/password_policy.py` (ajouté lors du chantier sécurité) exige aussi
majuscule/minuscule/chiffre/caractère spécial.

**Après** : ajout d'un texte d'aide sous le champ mot de passe dans `users.html` et
`profile.html`, et mise à jour du texte du `prompt()` de réinitialisation admin —
tous mentionnent désormais la vraie politique.

**Vérifié** : texte d'aide présent et correct sur les deux formulaires, en direct dans
le navigateur.

### Séparateur visuel dans la sidebar admin

**Avant** : les 7 liens de la sidebar admin (workflow d'audit + outils
d'administration) s'enchaînaient sans distinction visuelle.

**Après** : `border-top border-secondary mt-2 pt-2` ajouté au `<li>` "Utilisateurs"
(`base.html`) — sépare visuellement le bloc Dashboard→Comparaison du bloc
Utilisateurs/Logs, même convention que le séparateur déjà utilisé en bas de sidebar.

**Vérifié** : classes présentes en direct sur l'élément, aucune erreur console sur les
3 pages testées (Utilisateurs, Rapports, Mon profil).

---

## Journal des correctifs Phase 2

### Câblage frontend de `must_change_password`

**Avant** : le backend bloque déjà toutes les routes (sauf `/api/users/me`,
`/api/users/me/password`, `/api/auth/logout`) tant que `must_change_password` est actif,
mais rien côté front ne le savait — un utilisateur dans ce cas atterrissait sur son
dashboard habituel, dont les appels API échouaient silencieusement en 403, sans aucun
message expliquant pourquoi.

**Après** :
- `nexussecure.js::fillSidebarUser()` — le fetch existant vers `/api/users/me` (déjà là
  pour afficher le nom d'utilisateur) vérifie maintenant `must_change_password` et
  redirige vers `/profile` si actif et qu'on n'y est pas déjà.
- `profile.html` — bandeau non fermable (`#must-change-banner`, `alert-warning`)
  affiché quand `must_change_password` est vrai, expliquant pourquoi l'utilisateur est
  là et que le reste de l'app reste inaccessible tant que le mot de passe n'est pas
  changé.
- `profile.html` — le bandeau disparaît immédiatement après un changement de mot de
  passe réussi (en plus du flag qui se lève côté backend), sans attendre un rechargement
  de page.

**Vérifié** : scénario complet rejoué en direct avec un compte `must_change_password=True` —
login → redirection automatique vers `/profile` avec le bandeau visible → tentative de
naviguer vers `/scans` → renvoyé vers `/profile` → changement de mot de passe → bandeau
disparaît → navigation vers `/scans` cette fois réussie, aucune erreur.

**Limite connue** : la redirection dépend d'un appel réseau asynchrone
(`fetch("/api/users/me")`), donc si l'utilisateur atterrit brièvement sur une autre page
avant que la réponse n'arrive, le script de cette page peut tenter un appel qui échoue en
403 avant que la redirection ne le sorte de là — un bref éclair d'erreur console possible,
sans conséquence visible pour l'utilisateur (la redirection suit de très près). Pas
corrigé ici : nécessiterait de bloquer le rendu de la page le temps de la vérification,
ce qui ajouterait une latence perceptible à *chaque* chargement de page pour un cas qui
n'arrive qu'au tout premier login.

---

## Journal des correctifs Phase 3

### Système de composants partagés (`nexussecure.js`, `nexussecure.css`)

Ajout de 5 fonctions réutilisables, disponibles sur toutes les pages qui étendent
`base.html` :
- `showToast(message, type)` — notification Bootstrap Toast en haut à droite,
  auto-disparition après 4.5s, types success/danger/warning/info avec icône et couleur
  dédiées.
- `confirmModal(message)` → `Promise<boolean>` — modale de confirmation réutilisable
  (une seule instance recréée à chaque appel), remplace `confirm()`.
- `promptModal(title, options)` → `Promise<string|null>` — modale avec champ de saisie
  (texte/mot de passe), remplace `prompt()`.
- `tableSkeleton(tbody, cols, rows)` — lignes de tableau grisées animées, affichées
  pendant le chargement.
- `tableEmpty(tbody, cols, message, icon)` — état vide explicite (icône + message) au
  lieu d'un tableau simplement vide.

CSS ajouté : `.skeleton-bar` (pulsation via `@keyframes skeleton-pulse`, désactivée si
`prefers-reduced-motion`), `.empty-state`.

**Décision de périmètre** : seuls les vrais `alert()`/`confirm()`/`prompt()` natifs du
navigateur ont été remplacés. Les blocs `.alert` persistants déjà en thème (formulaires
de création scan/utilisateur, changement de mot de passe) n'ont pas été touchés — ils ne
posaient pas le problème "hors-thème" identifié dans l'audit, et les convertir aurait
élargi le chantier sans bénéfice clair.

### Remplacement des popups natives (9 appels sur 5 pages)

| Fichier | Avant | Après |
|---|---|---|
| `scans.html` | `confirm()` suppression scan | `confirmModal()` + `showToast()` de confirmation |
| `scans.html` | `alert()` ×2 (rapport indisponible, erreur téléchargement) | `showToast()` warning/danger |
| `users.html` | `prompt()` reset mot de passe | `promptModal()` avec le même indice que le formulaire de création |
| `users.html` | `alert()` ×2 (validation, erreur) | `showToast()` |
| `users.html` | `confirm()` suppression utilisateur | `confirmModal()` + `showToast()` |
| `users.html` | *(aucun retour)* activer/désactiver | `showToast()` ajouté (n'existait pas avant) |
| `reports.html` | `alert()` ×3 (téléchargement, email) | `showToast()` |
| `vulnerabilities.html` | `alert()` erreur commentaire | `showToast()` + succès ajouté (n'existait pas avant) |
| `compare.html` | `alert()` sélection invalide | `showToast()` warning |

### Skeletons + états vides (5 tableaux)

`scans.html`, `users.html`, `reports.html`, `vulnerabilities.html`,
`dashboard.html` (les deux tableaux : vue admin et vue analyste) affichent maintenant un
skeleton pendant le premier chargement, puis soit les données, soit un état vide explicite
("Aucun scan pour l'instant.", "Aucun utilisateur.", etc.) au lieu d'un tableau nu.
Pour `scans.html`, qui rafraîchit toutes les 10s, le skeleton n'apparaît qu'au tout
premier chargement (pas à chaque poll, pour éviter le clignotement).

### `.table-responsive` partout

Ajouté sur les 4 tableaux qui ne l'avaient pas (`reports.html`, `vulnerabilities.html`,
`scans.html` — y compris le tableau de ports dans la modale de détail — et `users.html`),
plus le tableau analyste du Dashboard qui avait été oublié lors de l'ajout initial côté
admin.

**Vérifié en direct**, méthodiquement composant par composant :
- `confirmModal()` — testé annulation (rien supprimé, 7 lignes intactes) et confirmation
  (`true` résolu) de façon isolée.
- `promptModal()` — testé un vrai reset de mot de passe de bout en bout : mot de passe
  effectivement changé en base (`verify_password` positif) et `must_change_password`
  correctement remis à `True`.
- `deleteUser` — testé une vraie suppression : utilisateur de test effectivement retiré
  de la base après confirmation.
- `showToast()` — apparition et disparition automatique confirmées.
- `tableSkeleton()`/`tableEmpty()` — rendu et styles calculés (couleur, animation)
  vérifiés directement.
- `.table-responsive` — présence confirmée sur les 6 tableaux concernés.
- Aucune erreur console sur les 6 pages parcourues.

Comptes de test jetables nettoyés après vérification (aucune trace laissée en base).

---

## Journal des correctifs Phase 4

### Contrôleur de tableau partagé (`createTableController`, `nexussecure.js`)

Recherche + tri + pagination côté client, réutilisable : les données sont déjà chargées
en une fois (petits volumes), le contrôleur filtre/trie/pagine en mémoire et redessine
via un callback `onRender`. Fonctions associées : `renderPaginationControls`,
`wireSortableHeaders` (en-têtes `<th data-sort="...">` cliquables), `updateSortIndicator`
(icône ▲/▼), `toCSV`/`downloadCSV` (export, avec BOM UTF-8 pour les accents dans Excel).
Le rafraîchissement en arrière-plan (`setData(data, resetPage=false)`) ne réinitialise
pas la page courante — important pour `scans.html`, qui recharge toutes les 10s.

### Appliqué à Scans, Utilisateurs, Rapports

| Page | Recherche sur | Tri | Filtre additionnel | Export CSV |
|---|---|---|---|---|
| `scans.html` | Cible | #, Cible, Statut, Hôtes, Date | Statut (pending/running/completed/failed) | Oui |
| `users.html` | Username, Email | #, Username, Email, Rôle, Statut | — | Oui |
| `reports.html` | # de scan | #, Scan, Score, Date | — | Oui |
| `vulnerabilities.html` | *(filtres serveur existants conservés)* | — | — | Oui (ajouté au filtre existant) |

`vulnerabilities.html` n'a pas été migré vers le contrôleur client — elle filtre déjà
côté serveur (scan + sévérité) via l'API, un pattern différent mais tout aussi valide ;
seul l'export CSV du résultat actuellement affiché a été ajouté, pour rester cohérent
sans dupliquer une logique de filtre qui fonctionne déjà bien.

### Centre de notifications global (topbar)

Cloche dans `base.html`, visible sur toutes les pages authentifiées. Réutilise
`/api/dashboard/alerts` (même endpoint que le panneau du Dashboard) et la **même clé
`localStorage`** de suppression (`nexus_dismissed_alerts`) — masquer une alerte à un
endroit la masque partout. Rafraîchi toutes les 30s. Le panneau détaillé du Dashboard
n'a pas été retiré : la cloche est une vue rapide toujours accessible, pas un
remplacement.

### Badge "nouveaux rapports"

`/api/reports/new-count` (existait côté backend, jamais appelé côté front) est
maintenant utilisé pour poser un badge numérique sur le lien "Rapports"/"Mes rapports"
dans les 3 sidebars (marquées `class="reports-nav-link"`).

**Vérifié en direct** :
- Recherche, tri (asc/desc avec icône), export CSV testés avec les vraies données de
  seed sur les 3 pages.
- Filtre statut sur Scans testé (état vide correct quand aucun scan ne correspond).
- Pagination testée avec un jeu de données synthétique de 23 lignes (5 pages, page 1 =
  items 1-5, dernière page correctement tronquée à 3 items, boutons précédent/suivant
  correctement activés/désactivés) — le seed réel a moins de 10 lignes par table donc
  la pagination ne s'affiche pas encore en pratique, mais le mécanisme est prouvé.
- Badge "nouveaux rapports" : généré un vrai rapport de test, badge passé de invisible à
  "1" après rechargement, confirmé.
- Cloche de notifications : rendu vérifié, aucune alerte affichée correctement quand il
  n'y en a pas.
- Aucune erreur console sur les 5 pages parcourues.

Rapport de test et son PDF supprimés après vérification ; compte de test nettoyé.

---

## Journal des correctifs Phase 5

### Indicateur de dernière mise à jour

`scans.html` (poll 10s) et `logs.html` (poll 15s) affichent maintenant "Actualisé à
HH:MM:SS", mis à jour à chaque cycle de rafraîchissement réussi.

### Historique du score par cible

Nouveau graphique en ligne sur le dashboard client ("Évolution du score de risque"),
entre les priorités et la liste des rapports. Réutilise les données déjà chargées par
`/api/reports/` (aucun nouvel endpoint) — pas assez d'historique (< 2 rapports) affiche
un état vide explicite au lieu d'un graphique vide/trompeur.

### Mode clair

Palette claire complète ajoutée dans `nexussecure.css` sous `:root[data-theme="light"]`,
activée par un bouton dans la topbar (`base.html`) et persistée en `localStorage`
(`nexus-theme`). Un script inline dans le `<head>` applique le thème avant le premier
rendu pour éviter un flash sombre→clair.

**Décision d'implémentation** : plutôt que de réécrire les classes Bootstrap codées en
dur (`bg-dark`, `text-white`, `border-secondary`, `table-dark`) dans les 9 templates, ces
classes sont redirigées vers les tokens de thème *uniquement quand `[data-theme="light"]`
est actif* — la même idée que `.text-fg`/`.text-fg-muted` ajoutées en Phase 1, étendue à
tout ce que Bootstrap fige en sombre. Ça couvre d'un coup les formulaires, modales et
tableaux de toute l'application sans toucher aux templates eux-mêmes.

Couleurs encore codées en dur trouvées et corrigées au passage (toasts, panneau de
notifications, graphiques Chart.js du dashboard/comparaison) — remplacées par
`var(--bg-card)`/`var(--text-primary)` ou une fonction `chartThemeColors()` dédiée pour
les graphiques (qui n'héritent pas du CSS). Le rechargement de page au changement de
thème (plutôt qu'une mise à jour à chaud) évite d'avoir à resynchroniser les graphiques
déjà rendus.

**Hors périmètre, choix assumé** : `login.html` (page pré-authentification, feuille de
style entièrement séparée et déjà conçue comme telle) et le panneau de logs
(`#log-container` dans `logs.html`), qui reste un panneau "terminal" sombre dans les deux
thèmes — comme un bloc de code, pas un défaut.

**Vérifié en direct**, page par page : bascule clair→sombre→clair confirmée
(`data-theme`, `localStorage`, icône du bouton) ; persistance testée à travers une
navigation complète (rechargement de `/users` après bascule) ; cartes, formulaires,
tableau, modale de confirmation (y compris le bouton de fermeture, qui doit se
ré-inverser) et toast tous vérifiés avec leurs couleurs calculées en mode clair ; sidebar
repliable re-testée en mode clair (fonctionne toujours, 62px) ; graphiques de
Comparaison et Vulnérabilités sans erreur console. Compte de test nettoyé, thème remis à
sombre par défaut à la fin.

---

## Correctif post-Phase 5 — contraste du mode clair

Signalé par l'utilisateur ("le mode clair n'est pas bien fait") après un premier tour de
test manuel. Investigation en direct plutôt que suppositions : un script de contraste
WCAG (ratio texte/fond calculé sur chaque élément visible) a été passé sur toutes les
pages en mode clair.

**Cause racine** : plusieurs couleurs "sémantiques" (sévérité, statut) sont calibrées
pour ressortir sur fond bleu-nuit — vert néon, cyan clair, ambre — et tombent à des ratios
de 1.6:1 à 2.6:1 une fois passées en texte sur fond blanc (le minimum WCAG AA est 4.5:1
pour du texte normal). Trouvé d'abord sur un score "0/100" en vert quasi invisible, puis
étendu à tout ce qui partage ces teintes :

| Trouvé sur | Élément | Ratio avant | Cause |
|---|---|---|---|
| Dashboard (toutes vues) | `scoreColor()`, panneau d'alertes, graphique de vulnérabilités, historique de score | 1.6–1.7:1 | Fonction JS retournant des hex fixes |
| Rapports, Scans, Utilisateurs | `.btn-outline-info`, `.btn-outline-warning` | 1.6–2:1 | Couleurs Bootstrap brutes (`--bs-info`/`--bs-warning`) |
| Comparaison | `.text-warning`, `.text-info` | 1.6–2:1 | Même cause, version "texte" de Bootstrap |
| Client (KPI "Risques élevés") | `.text-high` (ajoutée en Phase 1) | 2.57:1 | Jamais rendue dépendante du thème |
| Vulnérabilités | badge `HIGH` (texte blanc sur `#fd7e14`) | 2.57:1 | **Préexistant, indépendant du thème** — confirmé identique en sombre, non corrigé ici (hors périmètre "mode clair") |

**Corrigé** :
- `nexussecure.js` — nouvelle fonction `semanticColor(key)` avec une palette assombrie
  dédiée au mode clair (`critical`/`high`/`medium`/`low`/`safe`), utilisée partout où une
  couleur de sévérité était calculée en JS (`scoreColor`, alertes, graphiques, toasts).
- `nexussecure.css` — `.text-high`, `.text-warning`, `.text-info`,
  `.btn-outline-warning`, `.btn-outline-info` redirigés vers les mêmes teintes assombries
  sous `[data-theme="light"]` (ces deux derniers via les variables `--bs-btn-*` de
  Bootstrap 5.3 plutôt que de lutter contre sa spécificité).
- Suppression d'un `box-shadow` redondant sur la sidebar (doublonnait la bordure déjà
  correcte).

Toutes les nouvelles teintes vérifiées ≥ 4.5:1 sur blanc avant application (calcul de
luminance relative, pas au jugé).

**Vérifié en direct** avec le même script de contraste automatisé, cache CSS forcé à
chaque page pour écarter les faux positifs : Dashboard (admin, analyste, client), Scans,
Utilisateurs, Rapports, Vulnérabilités, Comparaison, Profil, Logs — **0 problème
restant**, à l'exception du badge `HIGH` préexistant signalé ci-dessus mais non traité
(hors périmètre de cette correction, affecte les deux thèmes également).

**Leçon retenue** : le premier passage "mode clair" avait vérifié la structure (tokens,
classes Bootstrap réécrites) mais pas le contraste réel des couleurs sémantiques
calculées en JavaScript, qui échappent entièrement au système de tokens CSS. À surveiller
pour tout futur ajout de couleur "de statut".

---

*Toutes les phases de `UI_UX_AUDIT.md` sont maintenant terminées.*
