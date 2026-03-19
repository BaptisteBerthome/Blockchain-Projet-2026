#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include "../include/blockchain_state.h"
#include "../include/blockchain_core.h"
#include "../include/utils.h"
#include "../include/bc_defines.h"
#include "../include/blockchain_io.h"

//Variable global a modifier

Blockchain blockchain;
Account wallets[MAX_USERS];
int nb_utilisateurs = 3;  // On commence avec 3 users : user1, user2, user3
bool est_prete = false;   // Pour éviter d'initialiser deux fois


//fonciton du menu (à compléter)

void action_initialiser() {
    printf("\n[INFO] Initialisation (Genesis + Helicopter Money)...\n");
    if (est_prete) {
            printf("\n[!] La blockchain est deja en route !\n");
            return;
        }
    //Configuration initiale
    blockchain.difficulty = 4; //Nombre de zéros requis
    blockchain.blocklist = NULL;
    blockchain.nbBlocks = 0;

    //Création des portefeuilles
    init_wallets(wallets, nb_utilisateurs);

    //Création du bloc Genesis
    create_genesis_block(&blockchain);

    //Distribution de l'argent de départ
    run_helicopter_money(&blockchain, wallets, nb_utilisateurs);

    est_prete = true;
    printf("\n[OK] Blockchain initialisee avec succès.\n");
    print_wallets(wallets, nb_utilisateurs);
}

void action_nouvelle_tx() {
    printf("\n[INFO] Creation d'une transaction...\n");
}

void action_verifier() {
    printf("\n[INFO] Verification de la chaine...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }

    printf("vérification de la chaine...\n");

    // On appelle la fonction de core qui fait le travail mathématique
    if (verify_chain_integrity(&blockchain)) {
        printf("CHAINE VALIDE\n");
    } else {
        printf("ALERTE : CHAINE CORROMPUE\n");
    }

}

void action_sauvegarder() {
    printf("\nSauvegarde JSON...\n");
    if (!est_prete) {
        printf("Initialise la blockchain dabord.\n");
        return;
    }
    printf("\n[Sauvegarde en cours dans 'blockchain.json'...\n");
    save_blockchain_json("blockchain.json", &blockchain, wallets, nb_utilisateurs);
    printf("Fichier enregistre avec succes !\n");
}

void action_quitter() {
    printf("Fermeture et nettoyage de la memoire...\n");
}


//main
int main() {
    srand(time(NULL));
    printf("=== Bienvenue dans BIT-THUNE (Projet Blockchain 2026) ===\n");

    int choix = 0;

    //choix
    while (choix != 5) {
        printf("\n=== MENU PRINCIPAL ===\n");
        printf("1. Initialiser la blockchain\n");
        printf("2. Creer une nouvelle transaction\n");
        printf("3. Verifier la chaine\n");
        printf("4. Sauvegarder en JSON\n");
        printf("5. Quitter\n");
        printf("Votre choix : ");
        
        //sécurité si l'utilisateur tape une lettre au lieu d'un chiffre
        if (scanf("%d", &choix) != 1) {
            while(getchar() != '\n');
            printf("Entree invalide, veuillez taper un chiffre.\n");
            continue;
        }


        //switch des choix
        switch (choix) {
            case 1:
                action_initialiser();
                break;
            case 2:
                action_nouvelle_tx();
                break;
            case 3:
                action_verifier();
                break;
            case 4:
                action_sauvegarder();
                break;
            case 5:
                action_quitter();
                break;
            default:
                printf("Choix invalide. Veuillez taper un chiffre entre 1 et 5.\n");
                break;
        }
    }

    return 0;
}