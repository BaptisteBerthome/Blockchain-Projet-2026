#ifndef BLOCKCHAIN_CORE_H
#define BLOCKCHAIN_CORE_H

#include <stdbool.h>
#include "blockchain_app.h"

void hash_text(const char *text, char out_hash[HASHLENGTH]);
void tx_compute_id(Transaction *tx);
bool starts_with_zeros(const char *hex_hash, int zeros);
void compute_merkle_root(const Slist *tx_list, int tx_count, char out_root[HASHLENGTH]);
void compute_block_hash(const Block *block, char out_hash[HASHLENGTH]);
void mine_block(Block *block, int difficulty);
bool verify_chain_integrity(const AppState *app);

#endif
