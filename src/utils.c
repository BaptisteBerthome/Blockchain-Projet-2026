#include "utils.h"

static void free_tx_outputs_list(Slist *list) {
    Slist *current = list;
    while (current != NULL) {
        Slist *next = current->next;
        TxOutputs *out = (TxOutputs *)current->info;
        if (out != NULL) {
            for (int i = 0; i < SCRIPTPUBKEY_SIZE; i++) {
                free(out->lockingScript[i]);
            }
            free(out);
        }
        free(current);
        current = next;
    }
}

static void free_tx_inputs_list(Slist *list) {
    Slist *current = list;
    while (current != NULL) {
        Slist *next = current->next;
        Utxo *in = (Utxo *)current->info;
        if (in != NULL) {
            for (int i = 0; i < SCRIPTSIG_SIZE; i++) {
                free(in->scriptSig[i]);
            }
            free(in);
        }
        free(current);
        current = next;
    }
}

//Ajouter un élément à la fin de la liste
Slist* Slist_add(Slist *list, void *new_info) {
    Slist *new_node = (Slist*)malloc(sizeof(Slist));
    if (new_node == NULL) {
        printf("Erreur d'allocation mémoire pour Slist\n");
        return list;
    }
    
    new_node->info = new_info;
    new_node->next = NULL;

    //si la liste est vide le nouveau noeud devient le premier
    if (list == NULL) {
        return new_node;
    }

    //parcourt jusqu'à la fin
    Slist *current = list;
    while (current->next != NULL) {
        current = current->next;
    }
    
    //on accroche le nouveau neod à la fin
    current->next = new_node;
    
    return list;
}

//Compte les éléments (utile pour nbTx et nbBlocks)
int Slist_count(Slist *list) {
    int count = 0;
    Slist *current = list;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    return count;
}


//Libérer les structure, pas le contenue dans ->info
void Slist_free_nodes(Slist *list) {
    Slist *current = list;
    Slist *next_node;

    while (current != NULL) {
        next_node = current->next;
        free(current);
        current = next_node;
    }
}

//Libérer un seul bloc et son contenue (toute les transaction)
void free_block(Block *b) {
    if (b == NULL) return;

    //je parcours la liste des transactions du bloc
    Slist *current_tx_node = b->transactions;
    while (current_tx_node != NULL) {


        Slist *next_tx_node = current_tx_node->next;
        Transaction *tx = (Transaction *)current_tx_node->info;
        
        if (tx != NULL) {
            free_tx_inputs_list(tx->lstInputs);
            free_tx_outputs_list(tx->lstOutputs);
            free(tx);
        }
        free(current_tx_node);
        
        current_tx_node = next_tx_node;
    }

    //bloc vide on le libere
    free(b);
}

//libere toute la blockchain

void free_blockchain(Blockchain *bc) {

    if (bc == NULL) return;

    //Parcours la list des blocs
    Slist *current_block_node = bc->blocklist;
    while (current_block_node != NULL) {


        Slist *next_block_node = current_block_node->next;
        
        //on libere le bloc
        if (current_block_node->info != NULL) {
            free_block((Block *)current_block_node->info); 
        }
        //On libere la srcuture
        free(current_block_node);
        
        current_block_node = next_block_node;
    }
}
