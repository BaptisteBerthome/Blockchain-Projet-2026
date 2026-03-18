#include <stdio.h>
#include <stdlib.h>
#include "bc_defines.h"
#include "utils.h"

//fonciton du menu (à compléter)

void action_initialiser() {
    printf("\n[INFO] Initialisation (Genesis + Helicopter Money)...\n");
}

void action_nouvelle_tx() {
    printf("\n[INFO] Creation d'une transaction...\n");
}

void action_verifier() {
    printf("\n[INFO] Verification de la chaine...\n");
}

void action_sauvegarder() {
    printf("\n[INFO] Sauvegarde JSON...\n");
}

void action_quitter() {
    printf("\n[INFO] Fermeture et nettoyage de la memoire...\n");
}


//main
int main() {
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