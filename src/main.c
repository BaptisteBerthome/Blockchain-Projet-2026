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
Block *pending_block = NULL; // Bloc courant qui recoit les nouvelles transactions

static const char *pick_random_miner_name(void) {
    if (nb_utilisateurs <= 0) {
        return "Miner";
    }
    int random_id = rand() % nb_utilisateurs;
    return wallets[random_id].str;
}

static long get_effective_balance_with_pending(const char *wallet_name) {
    int wallet_id = find_wallet_by_name(wallets, nb_utilisateurs, wallet_name);
    if (wallet_id == -1) {
        return -1;
    }

    long effective_balance = wallets[wallet_id].balance;
    if (pending_block == NULL) {
        return effective_balance;
    }

    Slist *node = pending_block->transactions;
    while (node != NULL) {
        Transaction *tx = (Transaction *)node->info;

        if (strcmp((char *)tx->adSender, wallet_name) == 0) {
            effective_balance -= tx->txAmount;
        }
        if (strcmp((char *)tx->adReceiver, wallet_name) == 0) {
            effective_balance += tx->txAmount;
        }

        node = node->next;
    }

    return effective_balance;
}

static Block *create_pending_block(const Blockchain *bc) {
    Block *b = malloc(sizeof(Block));
    if (b == NULL) {
        return NULL;
    }

    memset(b, 0, sizeof(Block));
    b->index = bc->nbBlocks;
    b->timestamp = (long)time(NULL);
    snprintf(b->minerName, MAX_STRING, "%s", pick_random_miner_name());

    if (bc->blocklist == NULL) {
        snprintf((char *)b->previousHash, HASHLENGTH, "0");
    } else {
        Slist *last = bc->blocklist;
        while (last->next != NULL) {
            last = last->next;
        }
        Block *prev = (Block *)last->info;
        snprintf((char *)b->previousHash, HASHLENGTH, "%s", prev->blockHash);
    }

    return b;
}


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

    blockchain.reward4mining = INITIALREWARD;

    pending_block = create_pending_block(&blockchain);
    if (pending_block == NULL) {
        printf("[ERREUR] Impossible de preparer le prochain bloc.\n");
        return;
    }

    est_prete = true;
    printf("\n[OK] Blockchain initialisee avec succès.\n");
    print_wallets(wallets, nb_utilisateurs);
}

void action_nouvelle_tx() {
    printf("\n[INFO] Creation d'une transaction...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }
    char sender[MAX_STRING];
    char receiver[MAX_STRING];
    long amount;
    char comment[MAX_STRING];
    printf("Entrez le nom de l'envoyeur (ex: user1) : ");
    scanf("%s", sender);
    printf("Entrez le nom du receveur (ex: user2) : ");
    scanf("%s", receiver);
    printf("Entrez le montant en Bit-Thunes : ");
    scanf("%ld", &amount);
    printf("Entrez un commentaire pour la transaction : ");
    scanf("%s", comment);

    if (pending_block == NULL) {
        printf("Aucun bloc courant disponible pour ajouter la transaction.\n");
        return;
    }

    if (find_wallet_by_name(wallets, nb_utilisateurs, sender) == -1 ||
        find_wallet_by_name(wallets, nb_utilisateurs, receiver) == -1) {
        printf("Sender/receiver invalide. Utilisez des noms user1..user%d\n", nb_utilisateurs);
        return;
    }

    if (amount <= 0) {
        printf("Le montant doit etre strictement positif.\n");
        return;
    }

    long sender_effective_balance = get_effective_balance_with_pending(sender);
    if (sender_effective_balance < amount) {
        printf("Solde insuffisant pour %s: disponible=%ld, demande=%ld\n",
               sender, sender_effective_balance, amount);
        return;
    }

    add_transaction_to_block(pending_block, sender, receiver, amount, comment);
    printf("\n[OK] Transaction ajoutee au bloc en cours.\n");

    if (pending_block->nbTx >= MAXTX) {
        printf("[INFO] Bloc courant plein (%d tx), minage automatique...\n", MAXTX);
        pending_block->timestamp = (long)time(NULL);
        mine_and_add_block(&blockchain, pending_block, wallets, nb_utilisateurs);
        pending_block = create_pending_block(&blockchain);
        if (pending_block == NULL) {
            printf("[ERREUR] Le bloc a ete mine, mais impossible de preparer le prochain.\n");
        }
        print_wallets(wallets, nb_utilisateurs);
    }


}

void action_mine_and_add_block() {
    printf("\n[INFO] Minage et ajout d'un nouveau bloc...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }
    if (pending_block == NULL) {
        printf("Aucun bloc courant a miner.\n");
        return;
    }

    if (pending_block->nbTx <= 0) {
        printf("Le bloc courant est vide. Ajoutez au moins une transaction avant de miner.\n");
        return;
    }

    pending_block->timestamp = (long)time(NULL);
    mine_and_add_block(&blockchain, pending_block, wallets, nb_utilisateurs);

    pending_block = create_pending_block(&blockchain);
    if (pending_block == NULL) {
        printf("[ERREUR] Le bloc a ete mine, mais impossible de preparer le prochain.\n");
    }

    printf("\n[OK] Nouveau bloc mine et ajoute a la blockchain.\n");
    print_wallets(wallets, nb_utilisateurs);
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

    if (pending_block != NULL && pending_block->nbTx > 0) {
        printf("\n[INFO] Bloc courant non vide detecte, minage automatique avant sauvegarde...\n");
        pending_block->timestamp = (long)time(NULL);
        mine_and_add_block(&blockchain, pending_block, wallets, nb_utilisateurs);
        pending_block = create_pending_block(&blockchain);
        if (pending_block == NULL) {
            printf("[ERREUR] Sauvegarde poursuivie, mais aucun nouveau bloc courant n'a pu etre prepare.\n");
        }
    }

    printf("\n[Sauvegarde en cours dans 'blockchain.json'...\n");
    save_blockchain_json("blockchain.json", &blockchain, wallets, nb_utilisateurs);
    printf("Fichier enregistre avec succes !\n");
}

void action_quitter() {
    if (est_prete) {
        printf("Sauvegarde automatique avant fermeture...\n");
        action_sauvegarder();
    }
    printf("Fermeture et nettoyage de la memoire...\n");

    free_blockchain(&blockchain);

    free(pending_block); 
    pending_block = NULL;
}


//main
int main() {
    srand(time(NULL));
    printf("=== Bienvenue dans BIT-THUNE (Projet Blockchain 2026) ===\n");

    int choix = 0;

    //choix
    while (choix != 6) {
        printf("\n=== MENU PRINCIPAL ===\n");
        printf("1. Initialiser la blockchain\n");
        printf("2. Creer une nouvelle transaction\n");
        printf("3. Miner et ajouter un nouveau bloc\n");
        printf("4. Verifier la chaine\n");
        printf("5. Sauvegarder en JSON\n");
        printf("6. Quitter\n");
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
                action_mine_and_add_block();
                break;
            case 4:
                action_verifier();
                break;
            case 5:
                action_sauvegarder();
                break;
            case 6:
                action_quitter();
                break;
            default:
                printf("Choix invalide. Veuillez taper un chiffre entre 1 et 5.\n");
                break;
        }
    }

    return 0;
}
