#include "../include/blockchain_core.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//------------PARTIT_HASH----------------------------------------------


// raccourcis de la fonction hash avec ajout de \0
void hash_text(const char *texte_a_hacher, BYTE resultat_hash[HASHLENGTH]) {
    char hash_tmp[HASHLENGTH];
    sha256ofString((BYTE *)texte_a_hacher, hash_tmp);
    memcpy(resultat_hash, hash_tmp, HASHLENGTH);
    resultat_hash[HASHLENGTH - 1] = '\0';
}


//calcul de l'id de la transaction
void tx_compute_id(Transaction *tx) {
   char buffer[512]; //tableau vide a hasher
   //remplissage tableau
   sprintf(buffer, "%lld|%s|%s|%ld|%s",
       (long long)tx->timestamp,
           tx->adSender,
           tx->adReceiver,
           tx->txAmount,
           tx->comment);


   //hash
   hash_text(buffer, tx->txid);
}


//hash le block
void compute_block_hash(const Block *block, BYTE result[HASHLENGTH]) {
   char buffer[1024];
   snprintf(
       buffer,
       sizeof(buffer),
       "%d|%s|%ld|%s|%s|%ld|%d|%ld",
       block->index,
    (char *)block->previousHash,
       (long)block->timestamp,
    (char *)block->merkleTree,
       block->minerName,
       block->nonce,
       block->nbTx,
       block->miningReward
   );
   hash_text(buffer, result);
}


//------------PARTIT_MINAGE----------------------------------------------



//verifie si le hash commence par le bon nombre de zero
bool starts_with_zeros(const BYTE *hash, int zeros) {
   for (int i = 0; i < zeros; i++) {
       if (hash[i] != '0') {
           return false;
       }
   }
   return true;
}


//fonction de minage
void mine_block(Block *block, int difficulty) {
   //racine des transactions
    compute_merkle_root(block->transactions, block->nbTx, block->merkleTree);
   block->nonce = 0;


   int is_mined = 0;
   while (is_mined == 0) {


       compute_block_hash(block, block->blockHash);


       if (starts_with_zeros(block->blockHash, difficulty) == true) {
           is_mined = 1;
       } else {
           block->nonce++;
       }
   }
}




void compute_merkle_root(const Slist *list_tx, int nb_tx, BYTE out_merkle_root[HASHLENGTH]) {
   //Cas exceptionnel pas de tx
   if (nb_tx <= 0) {
       hash_text("", out_merkle_root);
       return;
   }


    BYTE level[MAXTX][HASHLENGTH];
   int nb_hash = 0;


   //On recupere tout le shash des transactions
  
   const Slist *node = list_tx;
   while (node != NULL && nb_hash < nb_tx) {
       Transaction *tx = (Transaction *)node->info;
       strcpy((char *)level[nb_hash], (char *)tx->txid);
       nb_hash++;
       node = node->next;
   }


   //On monte les étage de l'arbre jusqu'à ce qui est plus qu'un seul hash
   while (nb_hash > 1) {
    BYTE next_level[MAXTX][HASHLENGTH];
       int nb_hash_suivant = 0;


       //On avance de 2 en 2 pour cree couple
       for (int i = 0; i < nb_hash; i += 2) {
           char hash[150]; // buffer assez grand pour contenir 2 hashs a la suite


           //Si on est sur le dernier élément tout seul(nombre impaire de tx)
           if (i + 1 == nb_hash) {
               //on le met en couple avec lui même
               sprintf(hash, "%s%s", level[i], level[i]);
           } else {
               //Sinon couple normal
               sprintf(hash, "%s%s", level[i], level[i+1]);
           }


           // On hache le couple pour créer la branche du niveau supérieur
           hash_text(hash, next_level[nb_hash_suivant]);
           nb_hash_suivant++;
       }


       // On met à jour pour le prochain tour de boucle (on monte d'un étage)
       for (int j = 0; j < nb_hash_suivant; j++) {
           strcpy((char *)level[j], (char *)next_level[j]);
       }
       nb_hash = nb_hash_suivant;
   }


   //boucle finit il reste qu'un seul hash (la racine)
    strcpy((char *)out_merkle_root, (char *)level[0]);


}






//verifie la chaine
bool verify_chain_integrity(Blockchain *bc) {
   if (bc == NULL) return false;


   Slist *current_node = bc->blocklist;
   Block *previous_block = NULL;
   int index = 0;


   // On parcourt tous les wagons (blocs) du train
   while (current_node != NULL) {
       Block *current_block = (Block *)current_node->info;


       //Est ce que quelqu'un a modifié une transaction dans ce bloc ?
       BYTE merkle_hash[HASHLENGTH];
       compute_merkle_root(current_block->transactions, current_block->nbTx, merkle_hash);
      
       if (strcmp((char *)merkle_hash, (char *)current_block->merkleTree) != 0) {
           printf("Bloc %d : Une transaction a ete modifiee (Merkle faux)\n", index);
           return false;
       }


       //Est  ce que les données du bloc correspondent a son hash ?
       BYTE hash_calcule[HASHLENGTH];
       compute_block_hash(current_block, hash_calcule);
      
       if (strcmp((char *)hash_calcule, (char *)current_block->blockHash) != 0) {
           printf("Bloc %d : Le hash du bloc est faux\n", index);
           return false;
       }


       //Est ce qu'on est bien accroché au bloc d'avant ? (Sauf Genesis)
       if (index > 0 && previous_block != NULL) {
          
           // Le "previousHash" de mon bloc actuel doit être égal au "blockHash" du bloc d'avant
           if (strcmp((char *)current_block->previousHash, (char *)previous_block->blockHash) != 0) {
               printf("Bloc %d : Lien casse avec le block precedent\n", index);
               return false;
           }
          


           //Est ce que le bloc respecte bien la difficulté ?
           if (starts_with_zeros(current_block->blockHash, bc->difficulty) == false) {
               printf("Bloc %d : La difficulté du minage est pas respectee\n", index);
               return false;
           }
       }


      
       previous_block = current_block;
       current_node = current_node->next;
       index++;
   }


   printf("La blockchain est valide\n");
   return true;
}
