#ifndef CORE_H
#define CORE_H

#include <stdbool.h>
#include "bc_defines.h" //On inclut le fichier intouchable du prof

void hash_text(char *texte_a_hacher, char resultat_hash[HASHLENGTH]);
void tx_compute_id(Transaction *tx);
bool starts_with_zeros(const char *hash, int zeros);
void compute_merkle_root(const Slist *list_tx, int nb_tx, char out_merkle_root[HASHLENGTH]);
void compute_block_hash(const Block *block, char result[HASHLENGTH]);
void mine_block(Block *block, int difficulty);

bool verify_chain_integrity(Blockchain *bc);

#endif
