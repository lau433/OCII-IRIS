# OCII-IRIS — HANDOFF

**Date** : 17 juin 2026  
**Auteur** : Session Cowork (Claude)  
**Projet** : OCII-IRIS — Plateforme SOC interne OCII, La Réunion

---

## Ce qui a été fait

### 1. Optimisations backend (app.py)

- **Cache `/api/dashboard`** — TTL 10 secondes, clé basée sur `range|from_ts|to_ts`. Évite les recalculs sur refresh rapide ou double-clic.
- **Réduction payload OpenSearch** — `_source` filtering sur `get_recent_alerts()` : seuls les champs affichés sont retournés (timestamp, agent.name, rule.level, rule.description, rule.groups, data.srcip, etc.). Réduit la bande passante et le temps de parsing.
- **Nouvelle route `/api/agent_details/<agent_id>`** — Fusionne 3 appels Wazuh en parallèle via `ThreadPoolExecutor(max_workers=3)` :
  - `/agents?agents_list={id}` → métadonnées agent
  - `/syscollector/{id}/os` → OS, hostname, architecture, kernel
  - `/syscollector/{id}/hardware` → CPU (modèle, cœurs, MHz), RAM (total, libre, % usage), serial
  - Cache 120 secondes par agent (hardware/OS changent rarement).

### 2. Refonte UI/UX premium (tous les templates)

**Direction** : passer de l'esthétique "terminal hacker" à un "executive security command center".

- **base.html** — Refonte complète :
  - Palette premium : `--bg:#0b1016`, `--surface-1:#101823`, `--accent:#28c7e8`, `--danger:#d85f74`, `--success:#36d98a`, `--warning:#d8a24a`
  - Typographie : Inter (sans) + JetBrains Mono (mono), suppression de Bebas Neue / IBM Plex Mono / Space Grotesk
  - Suppression des scan lines (`body::before` grid pattern)
  - Nav : `border-radius:6px`, `backdrop-filter:blur(12px)`, `font-weight:500`
  - Skeleton loader (shimmer animation) + `fade-in` utility
  - Aliases de compatibilité (`--void`, `--cyan`, `--hot`, etc.) pour ne pas casser les templates non migrés

- **agents.html** — Réécriture complète :
  - Lignes expandables : clic → panneau détail Syscollector via `/api/agent_details/<id>`
  - 3 colonnes : Système (hostname, OS, version, arch, kernel), Hardware (CPU, RAM avec barre usage), Agent Wazuh (ID, IP, groupes, dates)
  - Skeleton loaders pendant le chargement des détails
  - Cache côté client (`detailCache`)
  - Badges statut pill-style avec `border-radius:12px`

- **index.html** — Mise à jour CSS :
  - Time bar, stat cards, section headers, alert feed, panels, agent grid, boutons → tous avec `border-radius:6-10px`, Inter font, tailles ajustées

- **alerts.html** — Mise à jour CSS complète :
  - Boutons, filtres, table, badges de niveau → design premium avec border-radius, nouvelle palette, tailles lisibles

- **history.html** — Mise à jour CSS + contenu :
  - Cards avec `border-radius:8px`, typographie Inter, couleurs premium
  - Suppression du ALL CAPS dans les labels statiques

- **investigate.html** — Mise à jour CSS complète :
  - Panels avec `border-radius:8px`, panel headers avec `border-radius:8px 8px 0 0`
  - Verdict box avec `border-radius:10px`
  - MITRE box, recommandations, IOC tags, commandes → tous arrondis
  - Chips avec `border-radius:6px`
  - Couleurs alignées sur la nouvelle palette

### 3. Bug fix (session précédente)

- **Alerte introuvable** — Le bug venait de la requête OpenSearch `ids` query qui ne fonctionnait pas correctement. Corrigé avec une recherche par `_id` + `_index`.

---

## Ce qui reste à faire

### Priorité haute

1. **Rebuild Docker** — Les modifications UI ne sont pas encore déployées. Exécuter `rebuild.bat` depuis `C:\ocii-iris`.
2. **Vérification visuelle** — Après rebuild, vérifier chaque page dans Chrome (dashboard, agents, alertes, historique, investigation).

### Priorité moyenne

3. **Skeleton loaders sur le dashboard** — Seule la page agents a des skeleton loaders. Ajouter le même pattern sur index.html (stat cards, alert feed, agent grid).
4. **Auto-refresh doux** — Actuellement le refresh remplace brutalement le DOM. Implémenter un diff/merge pour éviter le flash (surtout sur alerts.html et index.html).
5. **investigate.html — contenu HTML** — Le CSS est mis à jour, mais certains labels dans le HTML utilisent encore des styles inline avec les anciennes couleurs. Vérifier et nettoyer.

### Priorité basse

6. **Login page** — Non touchée, utilise probablement un template séparé. À aligner sur le nouveau design.
7. **Responsive / mobile** — Aucun travail responsive n'a été fait. Les grids `g2` et la nav ne sont pas adaptés au mobile.
8. **Animations de transition entre pages** — Pas implémentées.

---

## Ce qui a été testé

- **Premier rebuild réussi** — Backend (cache dashboard, `_source` filtering, route agent_details) déployé et fonctionnel.
- **Second rebuild (UI)** — Non encore exécuté. Les fichiers sont écrits sur le disque mais le container Docker n'a pas été reconstruit.
- **Compatibilité CSS** — Les aliases dans `base.html` (`--void:var(--bg)`, `--cyan:var(--accent)`, etc.) assurent que les templates partiellement migrés continuent de fonctionner.

---

## Risques

1. **Aliases CSS** — Si un template utilise une variable non aliasée, elle sera invisible (transparent). Tous les principaux sont couverts, mais des edge cases sont possibles dans investigate.html (styles inline).
2. **Cache dashboard** — TTL 10s signifie que les données peuvent être stale de 10s max. Acceptable pour un SOC interne, mais à surveiller si le besoin temps réel devient critique.
3. **Cache agent_details** — TTL 120s. Si un agent change de statut (ex: déconnexion), l'info sera stale pendant 2 min max.
4. **`_source` filtering** — Si un futur développeur ajoute un champ à afficher dans le frontend sans l'ajouter à la liste `_source`, il sera silencieusement absent. Documenter la liste dans un commentaire.

---

## Prochaine priorité

**Rebuild + vérification visuelle**, puis implémenter les skeleton loaders sur le dashboard et l'auto-refresh doux pour finaliser le niveau "perceived performance" du brief.
