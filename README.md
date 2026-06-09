# ⛓️ Projet Blockchain

Projet réalisé dans le cadre de la licence informatique a l'université de Toulouse. L'objectif est de concevoir et d'implémenter une blockchain simplifié et fonctionnelle de A à Z.

## Présentation du Projet
Ce projet est une implémentation complète d'une blockchain centralisée nommée BitThune Le but du projet est d’implémenter, en plusieurs étapes, une crypto-monnaie de type Bitcoin. Outres la création des structures des données pour gérer cette monnaie, nous allons simuler des échanges économiques (transactions). La monnaie sera basée sur une blockchain car cette technologie est intéressante à connaître. Ce sera une blockchain simplifiée de type Bitcoin, mais : centralisée (pas de peer2peer), les mineurs seront simulés par un tirage aléatoire, pas de vote ni de consensus. En clair tout est sous contrôle, l’antithèse du Bitcoin.

* **Langage utilisé :** C

## Présentation de l'équipe 60
L'équipe 60 est composée de :
  - BENAMAR Fadi
  - BERTHOME Baptiste
  - GOUL Raphaël
  - JANET Aurélien
  - KAMYSH Artem

## Installation & Utilisation

### Prérequis
- GCC
- Make

### Compilation
Depuis la racine du projet il faut utiliser dans le terminal `make`. Un fichier `bitthune_exec` sera générer.

### Execution
Vous pouvez lancer l'application via `./bitthune_exec`.

Pour la modification du nombre d'utilisateurs il faut :
- Ce rendre dans `/include/bc_config.h` ligne 16, modifier le champ `MAX_USERS`.
- Ce rendre dans `/src/main.c` ligne 14, modifier le champ `nb_utilisateurs`.

## Performance & Limitations
Nous avons tester avec 100 utilisateurs sans aucun problème.

