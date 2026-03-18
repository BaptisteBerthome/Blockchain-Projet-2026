# ⛓️ Projet Blockchain

Projet réalisé dans le cadre de la licence informatique a l'université de Toulouse. L'objectif est de concevoir et d'implémenter une blockchain simplifié et fonctionnelle de A à Z.

## Présentation du Projet
Ce projet est une implémentation complète d'une blockchain décentralisée comprenant:

Partie 1
- gestion de blocs et transactions,
- minage (proof-of-work),
- vérification d'intégrité,
- export JSON,
- mode manuel + autotests.

Partie 2
- 
Partie 3
- 

- Langage utilisé: C

## Commandes Makefile

Depuis la racine du projet:

- make app: compile la version manuelle dans build/bin
- make run-manual: lance l'application interactive
- make test: compile le runner d'autotests dans build/bin
- make run-tests: exécute les autotests et génère le JSON
- make clean: supprime les binaires et les JSON générés

## Artifacts générés

- Binaires: build/bin
- JSON: build/json
- Exemple autotest: build/json/autotest_chain.json

## Structure du projet

- lib: utilitaires et SHA256
- src: coeur de l'application (menu, état, logique blockchain, I/O)
- tests: runner et scénarios d'autotest
- build/bin: exécutables générés
- build/json: exports JSON générés

### Détail du dossier src

- main.c: point d'entrée du programme et boucle du menu principal.
- blockchain_app.h / blockchain_app.c: interface utilisateur console, menu et orchestration des actions.
- blockchain_state.h / blockchain_state.c: gestion de l'état global (wallets, création de blocs, transactions, mémoire).
- blockchain_core.h / blockchain_core.c: logique blockchain (hash, merkle, minage, vérification d'intégrité).
- blockchain_io.h / blockchain_io.c: affichage et export JSON de la blockchain.

## Prérequis

- gcc
- make

