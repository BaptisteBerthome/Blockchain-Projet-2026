#include "utils.h"

//Ajouter un élément à la fin de la liste
Slist* Slist_add(Slist *list, void *new_info) {
    //allocation mémoire
    Slist *new_node = (Slist*)malloc(sizeof(Slist));
    if (new_node == NULL) {
        printf("Erreur d'allocation mémoire pour Slist\n");
        return list; //Echec
    }
    
    new_node->info = new_info; //Le pointeur générique pointe vers bloc ou transaction
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
//pasque on sait aps si c'est un bloc ou une tx
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
        
        //On libere le contenue
        if (current_tx_node->info != NULL) {
            free(current_tx_node->info); 
        }
        //libere la structure
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
