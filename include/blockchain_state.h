#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "bc_defines.h"

typedef struct s_tx_request {
	char sender[MAX_STRING];
	char receiver[MAX_STRING];
	long amount;
} TxRequest;

//Fonctions pour les portefeuilles
void init_wallets(Account wallets[MAX_USERS], int nb_users);
int find_wallet_by_name(Account wallets[MAX_USERS], int nb_users, const char *name);
int find_wallet_by_address(Account wallets[MAX_USERS], int nb_users, const char *address);
// Resolution hybride pour le menu : accepte une adresse OU un mnemonique "userX".
int resolve_account(Account wallets[MAX_USERS], int nb_users, const char *id);
// H(pubKey) d'un compte (== identite de l'adresse). 'out' >= HASH160_HEX_LEN.
void wallet_pubkeyhash(const Account *w, char *out);

//Fonctions pour les blocks
void add_transaction_to_block(Block *b, Account wallets[MAX_USERS], int nb_users,
	const char *sender, const char *receiver, long amount, const char *comment);
void create_genesis_block(Blockchain *bc);
void mine_and_add_block(Blockchain *bc, Block *new_block, Account wallets[MAX_USERS], int nb_users);

//Helicopter Money
void run_helicopter_money(Blockchain *bc, Account wallets[MAX_USERS], int nb_users);

// CC3 Part 2: UTXO and market phase
void reset_utxo_state(void);
bool add_utxo_transaction_to_block(
	Block *b,
	Account wallets[MAX_USERS],
	int nb_users,
	const char *sender,
	const char *receiver,
	long amount,
	const char *comment,
	long *out_fee,
	bool verbose // partie 3 : affiche l'execution des scripts
);
void add_coinbase_transaction(Block *b, Account wallets[MAX_USERS], int nb_users,
	const char *miner_name, long reward, long fees_collected);
void process_market_round(Blockchain *bc, Account wallets[MAX_USERS], int nb_users, int random_tx_count);

// CC4 Part 3: analyse de la blockchain pour reconstruire un wallet par adresse
void analyze_blockchain_for_address(Blockchain *bc, Account wallets[MAX_USERS],
	int nb_users, const char *address_or_name);

long get_money_supply(void);
long get_current_reward(void);
int get_halving_count(void);
int get_cycle_rounds(void);
void set_current_reward(long reward);
void increment_cycle_round(void);
void increment_halving_count(void);

#endif
