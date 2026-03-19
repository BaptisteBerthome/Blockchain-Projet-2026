#include "../include/blockchain_state.h"

#include "../include/blockchain_core.h"
#include "../include/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//----- GESTION DES PORTEFEUILLES-------



void init_wallets(Account wallets[MAX_USERS], int nb_users) {
    for (int i = 0; i < nb_users; i++) {
        sprintf(wallets[i].str, "user%d", i + 1);
        wallets[i].balance = 0; //Au début, personne n'a d'argent
    }
    printf("%d utilisateurs crees (user1 a user%d).\n", nb_users, nb_users);
}


int find_wallet_by_name(Account wallets[MAX_USERS], int nb_users, const char *name) {
    for (int i = 0; i < nb_users; i++) {
        if (strcmp(wallets[i].str, name) == 0) return i;
    }
    return -1; //wallet pas trouver
}

//-------- GESTION DES TRANSACTION---------

void add_transaction_to_block(Block *b, const char *sender, const char *receiver, long amount, const char *comment) {
    
    //On vérifie si le bloc n'est pas déjà plein
    //MAXTX défini dans bc_defines.h
    if (b->nbTx >= MAXTX) {
        printf("Le bloc est plein (%d tx)\n", MAXTX);
        return;
    }

    //Allocation mémoire pour la nouvelle transaction
    Transaction *tx = malloc(sizeof(Transaction));
    
    if (tx == NULL) {
        printf("Memoire insuffisante pour creer la transaction.\n");
        return;
    }

    //Remplissage
    tx->timestamp = (long)time(NULL); // Heure actuelle
    tx->txAmount = amount;            // Montant en Bit-Thunes

    //  utilise memcpy pour copier le texte
    // Le -1 laisse la plmace a \0
    memcpy(tx->adSender, sender, HASHLENGTH - 1);
    tx->adSender[HASHLENGTH - 1] = '\0';
    memcpy(tx->adReceiver, receiver, HASHLENGTH - 1);
    tx->adReceiver[HASHLENGTH - 1] = '\0';
    strncpy(tx->comment, comment, MAX_STRING - 1);
    tx->comment[MAX_STRING - 1] = '\0';

    //calcul de l'id/hash

    tx_compute_id(tx);

    //ajout de la transaction a la structure
    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;

    printf("Transaction ajoutee : %s -> %s (%ld BT)\n", sender, receiver, amount);
}

//------------CRÉATION DU GENESIS-----------------

void create_genesis_block(Blockchain *bc) {
    //allocation mémoire
    Block *genesis = malloc(sizeof(Block));
    if (genesis == NULL) {
        printf("Memoire insuffisante pour creer la transaction.\n");
        return;
    }
    
    //remplissage
    genesis->index = 0;
    genesis->timestamp = (long)time(NULL);
    genesis->nonce = 0; // Pas de minage pour le Genesis, on le force à 0
    
    //Ladresse précédente est 0 car il genesis
    snprintf((char *)genesis->previousHash, HASHLENGTH, "0");
    snprintf(genesis->minerName, MAX_STRING, "System");

    add_transaction_to_block(genesis, "Network", "Genesis", 0, "Initial Block");

    //calcul du hash
    compute_merkle_root(genesis->transactions, genesis->nbTx, (char *)genesis->merkleTree);
    compute_block_hash(genesis, (char *)genesis->blockHash);

    //ajout a la structure
    bc->blocklist = Slist_add(bc->blocklist, genesis);
    bc->nbBlocks = 1;

    printf("Block Genesis crée et ajouté avec succès.\n");
}

//------MINAGE ET MISE A JOUR DES SOLDES------

void mine_and_add_block(Blockchain *bc, Block *new_block, Account wallets[MAX_USERS], int nb_users) {
    //On mine le bloc(trouver la nonce)
    printf("Recherche de la nonce pour le bloc %d (mining...)\n", new_block->index);
    mine_block(new_block, bc->difficulty);

   //ajout a la structure
    bc->blocklist = Slist_add(bc->blocklist, new_block);
    bc->nbBlocks++;

    //mettre a jours les soldes des portefeuilles
    Slist *current = new_block->transactions;
    while (current != NULL) {
        Transaction *tx = current->info;
        
        //On enlève l'argent à l'envoyeur (qiue si c'est pas le systeme)
        int id_sender = find_wallet_by_name(wallets, nb_users, (char *)tx->adSender);
        if (id_sender != -1){
            wallets[id_sender].balance -= tx->txAmount;
        }

        //On donne l'argent au receveur
        int id_receiver = find_wallet_by_name(wallets, nb_users, (char *)tx->adReceiver);
        if (id_receiver != -1){
            wallets[id_receiver].balance += tx->txAmount;
        }

        current = current->next;
    }
}

// --- HELICOPTER MONEY ---

void run_helicopter_money(Blockchain *bc, Account wallets[MAX_USERS], int nb_users) {
    printf("Distribution de %d BT a tout le monde...\n", HELIREWARD);
    
    //nouveau bloc allocation
    Block *new_block = malloc(sizeof(Block));
    if (new_block == NULL) return;
    
    //nettoyer la memoir du malloc
    memset(new_block, 0, sizeof(Block));
    
    //Remplissage 
    new_block->index = bc->nbBlocks;
    new_block->timestamp = (long)time(NULL);
    snprintf(new_block->minerName, MAX_STRING, "Banque Centrale");
    
    //on cherche le hash du block precednat
    Slist *previous_node = bc->blocklist;
    while (previous_node->next != NULL) {
        previous_node = previous_node->next;
    }
    Block *previous_block = previous_node->info;
    
    //On copie le hash du bloc davant dans le nouveau bloc
    snprintf((char *)new_block->previousHash, HASHLENGTH, "%s",previous_block->blockHash);

    //création de tranqaction pour chaque users
    for (int i = 0; i < nb_users; i++) {
        // Coinbase est l'émetteur qui crée l'argent
        add_transaction_to_block(new_block, "Coinbase", wallets[i].str, HELIREWARD, "Distribution de départ ");
    }

    //on mine le bloc et l'ajoute officielement
    mine_and_add_block(bc, new_block, wallets, nb_users);

    printf("Tout le monde a recu ses Bit-Thunes\n");
}
