#include "../include/blockchain_core.h"
#include "../include/script.h"


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






//------------PARTIE_VALIDATION_UTXO----------------------------------------------
// Ensemble d'UTXO reconstruit pendant la verification (rejeu de la chaine).
typedef struct VEntry {
   char txid[HASHLENGTH];
   int index;
   TxOutputs *out; // pour acceder au scriptPubKey
   struct VEntry *next;
} VEntry;

static void vset_add(VEntry **set, const char *txid, int index, TxOutputs *out) {
   VEntry *e = malloc(sizeof(VEntry));
   if (e == NULL) return;
   snprintf(e->txid, HASHLENGTH, "%s", txid);
   e->index = index;
   e->out = out;
   e->next = *set;
   *set = e;
}

// Retire et renvoie l'UTXO (txid,index) s'il existe ; NULL sinon (=> manquant/double-spend).
static TxOutputs *vset_take(VEntry **set, const char *txid, int index) {
   VEntry *prev = NULL, *cur = *set;
   while (cur != NULL) {
       if (cur->index == index && strcmp(cur->txid, txid) == 0) {
           TxOutputs *out = cur->out;
           if (prev == NULL) *set = cur->next; else prev->next = cur->next;
           free(cur);
           return out;
       }
       prev = cur;
       cur = cur->next;
   }
   return NULL;
}

static void vset_free(VEntry *set) {
   while (set != NULL) {
       VEntry *next = set->next;
       free(set);
       set = next;
   }
}

static bool replay_utxo_model(Block *blk, VEntry **set) {
   Slist *tn = blk->transactions;
   while (tn != NULL) {
       Transaction *tx = (Transaction *)tn->info;
       ScriptContext ctx = { .message = (const char *)tx->txid };

       // 1) inputs : existence + script + pas de double-spend (+ somme des inputs)
       long in_sum = 0;
       Slist *in = tx->lstInputs;
       while (in != NULL) {
           Utxo *input = (Utxo *)in->info;
           TxOutputs *spent = vset_take(set, (const char *)input->hash, input->indexOutput);
           if (spent == NULL) {
               printf("Bloc %d : UTXO introuvable ou deja depense (double-spend) tx=%.12s.. index=%d\n",
                      blk->index, input->hash, input->indexOutput);
               return false;
           }
           if (!script_execute(input->scriptSig, spent->lockingScript, &ctx, false)) {
               printf("Bloc %d : script de depense invalide (signature/adresse) tx=%.12s..\n",
                      blk->index, tx->txid);
               return false;
           }
           in_sum += spent->amount;
           in = in->next;
       }

       // 2) outputs : somme + ajout des nouveaux UTXO (verrouilles par adresse)
       long out_sum = 0;
       Slist *on = tx->lstOutputs;
       while (on != NULL) {
           TxOutputs *o = (TxOutputs *)on->info;
           if (o != NULL) {
               out_sum += o->amount; // inclut la sortie FEE_POOL (la commission)
               if (o->pubKeyHash[0] != '\0') {
                   vset_add(set, (const char *)tx->txid, o->outIndex, o);
               }
           }
           on = on->next;
       }

       if (tx->lstInputs != NULL && in_sum < out_sum) {
           printf("Bloc %d : desequilibre (creation de monnaie) tx=%.12s.. inputs=%ld outputs=%ld\n",
                  blk->index, tx->txid, in_sum, out_sum);
           return false;
       }

       tn = tn->next;
   }
   return true;
}

//verifie la chaine
bool verify_chain_integrity(Blockchain *bc) {
   if (bc == NULL) return false;


   Slist *current_node = bc->blocklist;
   Block *previous_block = NULL;
   int index = 0;
   VEntry *utxo_set = NULL; // partie 3/4 : rejeu du modele UTXO


   // On parcourt tous les wagons (blocs) du train
   while (current_node != NULL) {
       Block *current_block = (Block *)current_node->info;


       //Est ce que quelqu'un a modifié une transaction dans ce bloc ?
       BYTE merkle_hash[HASHLENGTH];
       compute_merkle_root(current_block->transactions, current_block->nbTx, merkle_hash);

       if (strcmp((char *)merkle_hash, (char *)current_block->merkleTree) != 0) {
           printf("Bloc %d : Une transaction a ete modifiee (Merkle faux)\n", index);
           vset_free(utxo_set);
           return false;
       }


       //Est  ce que les données du bloc correspondent a son hash ?
       BYTE hash_calcule[HASHLENGTH];
       compute_block_hash(current_block, hash_calcule);

       if (strcmp((char *)hash_calcule, (char *)current_block->blockHash) != 0) {
           printf("Bloc %d : Le hash du bloc est faux\n", index);
           vset_free(utxo_set);
           return false;
       }


       //Est ce qu'on est bien accroché au bloc d'avant ? (Sauf Genesis)
       if (index > 0 && previous_block != NULL) {

           // Le "previousHash" de mon bloc actuel doit être égal au "blockHash" du bloc d'avant
           if (strcmp((char *)current_block->previousHash, (char *)previous_block->blockHash) != 0) {
               printf("Bloc %d : Lien casse avec le block precedent\n", index);
               vset_free(utxo_set);
               return false;
           }



           //Est ce que le bloc respecte bien la difficulté ?
           if (starts_with_zeros(current_block->blockHash, bc->difficulty) == false) {
               printf("Bloc %d : La difficulté du minage est pas respectee\n", index);
               vset_free(utxo_set);
               return false;
           }
       }


       // Validation complete du modele UTXO (existence + scripts + double-spend)
       if (!replay_utxo_model(current_block, &utxo_set)) {
           vset_free(utxo_set);
           return false;
       }


       previous_block = current_block;
       current_node = current_node->next;
       index++;
   }


   vset_free(utxo_set);
   printf("La blockchain est valide (Merkle + hash + liens + difficulte + scripts/UTXO + conservation valeur)\n");
   return true;
}
