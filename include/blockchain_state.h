#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "bc_defines.h"

//Fonctions pour les portefeuilles
void init_wallets(Account wallets[MAX_USERS], int nb_users);
int find_wallet_by_name(Account wallets[MAX_USERS], int nb_users, const char *name);

//Fonctions pour les blocks
void add_transaction_to_block(Block *b, const char *sender, const char *receiver, long amount, const char *comment);
void create_genesis_block(Blockchain *bc);
void mine_and_add_block(Blockchain *bc, Block *new_block, Account wallets[MAX_USERS], int nb_users);

//Helicopter Money
void run_helicopter_money(Blockchain *bc, Account wallets[MAX_USERS], int nb_users);

#endif
