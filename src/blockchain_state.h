#ifndef BLOCKCHAIN_STATE_H
#define BLOCKCHAIN_STATE_H

#include <stdbool.h>
#include "blockchain_app.h"

void init_wallets(AppState *app, int users);
int wallet_index_by_name(const AppState *app, const char *name);
int random_miner_index(const AppState *app);
void apply_transaction(AppState *app, const Transaction *tx);
long total_supply(const AppState *app);
void block_add_tx(Block *block, const char *sender, const char *receiver, long amount, const char *comment);
void create_genesis(AppState *app);
bool append_mined_block(AppState *app, Block *block);
void create_blockchain_with_users(AppState *app, int users);
bool create_user_transaction_by_name(AppState *app, const char *sender, const char *receiver, long amount);
bool mine_pending_block(AppState *app);
bool run_helicopter_money_internal(AppState *app);
Block *get_block_at(const AppState *app, int index);
void free_blockchain_memory(AppState *app);

#endif
