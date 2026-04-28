#include "../include/blockchain_state.h"

#include "../include/blockchain_core.h"
#include "../include/utils.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static Slist *g_utxo_pool = NULL;
static long g_money_supply = 0;
static long g_current_reward = INITIALREWARD;
static int g_halving_count = 0;
static int g_cycle_rounds = 0;

static char *bt_strdup(const char *s) {
    size_t len = strlen(s);
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len + 1);
    return copy;
}

static TxOutputs *create_tx_output(const char *owner, long amount, time_t ts) {
    TxOutputs *out = malloc(sizeof(TxOutputs));
    if (out == NULL) {
        return NULL;
    }

    memset(out, 0, sizeof(TxOutputs));
    out->amount = amount;
    out->timestamp = ts;
    out->lockingScript[0] = bt_strdup(owner);
    if (out->lockingScript[0] == NULL) {
        free(out);
        return NULL;
    }
    return out;
}

static void free_tx_output(TxOutputs *out) {
    if (out == NULL) {
        return;
    }
    for (int i = 0; i < LOCK_SCRIPT_SIZE; i++) {
        free(out->lockingScript[i]);
    }
    free(out);
}

static TxOutputs *clone_tx_output(const TxOutputs *src) {
    if (src == NULL || src->lockingScript[0] == NULL) {
        return NULL;
    }
    TxOutputs *copy = create_tx_output(src->lockingScript[0], src->amount, src->timestamp);
    if (copy == NULL) {
        return NULL;
    }
    copy->outIndex = src->outIndex;
    return copy;
}

static Utxo *create_utxo(const BYTE txid[HASHLENGTH], int out_index, TxOutputs *tx_out) {
    Utxo *u = malloc(sizeof(Utxo));
    if (u == NULL) {
        return NULL;
    }
    memset(u, 0, sizeof(Utxo));
    snprintf((char *)u->hash, HASHLENGTH, "%s", txid);
    u->indexOutput = out_index;
    u->txOut = tx_out;
    return u;
}

static void clear_utxo_pool(void) {
    Slist *node = g_utxo_pool;
    while (node != NULL) {
        Slist *next = node->next;
        Utxo *utxo = (Utxo *)node->info;
        if (utxo != NULL) {
            free_tx_output(utxo->txOut);
            free(utxo);
        }
        free(node);
        node = next;
    }
    g_utxo_pool = NULL;
}

static void recalculate_wallets_and_supply(Account wallets[MAX_USERS], int nb_users) {
    g_money_supply = 0;
    for (int i = 0; i < nb_users; i++) {
        wallets[i].balance = 0;
    }

    Slist *node = g_utxo_pool;
    while (node != NULL) {
        Utxo *utxo = (Utxo *)node->info;
        if (utxo != NULL && utxo->txOut != NULL && utxo->txOut->lockingScript[0] != NULL) {
            int idx = find_wallet_by_name(wallets, nb_users, utxo->txOut->lockingScript[0]);
            if (idx != -1) {
                wallets[idx].balance += utxo->txOut->amount;
                g_money_supply += utxo->txOut->amount;
            }
        }
        node = node->next;
    }
}

static bool remove_utxo_from_pool(const BYTE txid[HASHLENGTH], int out_index) {
    Slist *prev = NULL;
    Slist *node = g_utxo_pool;

    while (node != NULL) {
        Utxo *utxo = (Utxo *)node->info;
        if (utxo != NULL && strcmp((const char *)utxo->hash, (const char *)txid) == 0 && utxo->indexOutput == out_index) {
            if (prev == NULL) {
                g_utxo_pool = node->next;
            } else {
                prev->next = node->next;
            }
            free_tx_output(utxo->txOut);
            free(utxo);
            free(node);
            return true;
        }
        prev = node;
        node = node->next;
    }
    return false;
}

static bool append_output(Transaction *tx, const char *owner, long amount, time_t ts) {
    TxOutputs *out = create_tx_output(owner, amount, ts);
    if (out == NULL) {
        return false;
    }
    out->outIndex = tx->nbOutputs;
    tx->lstOutputs = Slist_add(tx->lstOutputs, out);
    tx->nbOutputs++;
    return true;
}

static bool append_input_reference(Transaction *tx, const Utxo *source) {
    Utxo *input_ref = malloc(sizeof(Utxo));
    if (input_ref == NULL) {
        return false;
    }
    memset(input_ref, 0, sizeof(Utxo));
    snprintf((char *)input_ref->hash, HASHLENGTH, "%s", source->hash);
    input_ref->indexOutput = source->indexOutput;
    tx->lstInputs = Slist_add(tx->lstInputs, input_ref);
    tx->nbInputs++;
    return true;
}

static bool is_utxo_owned_by(const Utxo *utxo, const char *owner) {
    return utxo != NULL && utxo->txOut != NULL && utxo->txOut->lockingScript[0] != NULL &&
           strcmp(utxo->txOut->lockingScript[0], owner) == 0;
}

static Block *create_empty_block(Blockchain *bc, const char *miner_name) {
    Block *block = malloc(sizeof(Block));
    if (block == NULL) {
        return NULL;
    }
    memset(block, 0, sizeof(Block));
    block->index = bc->nbBlocks;
    block->timestamp = time(NULL);
    snprintf(block->minerName, MAX_STRING, "%s", miner_name);
    return block;
}

void init_wallets(Account wallets[MAX_USERS], int nb_users) {
    for (int i = 0; i < nb_users; i++) {
        snprintf(wallets[i].str, MAX_STRING, "user%d", i + 1);
        wallets[i].balance = 0;
        wallets[i].utxoList = NULL;
    }
    printf("%d utilisateurs crees (user1 a user%d).\n", nb_users, nb_users);
}

int find_wallet_by_name(Account wallets[MAX_USERS], int nb_users, const char *name) {
    for (int i = 0; i < nb_users; i++) {
        if (strcmp(wallets[i].str, name) == 0) {
            return i;
        }
    }
    return -1;
}

void reset_utxo_state(void) {
    clear_utxo_pool();
    g_money_supply = 0;
    g_current_reward = INITIALREWARD;
    g_halving_count = 0;
    g_cycle_rounds = 0;
}

void add_transaction_to_block(Block *b, const char *sender, const char *receiver, long amount, const char *comment) {
    if (b == NULL || b->nbTx >= MAXTX || amount < 0) {
        return;
    }

    Transaction *tx = malloc(sizeof(Transaction));
    if (tx == NULL) {
        return;
    }
    memset(tx, 0, sizeof(Transaction));

    tx->timestamp = time(NULL);
    tx->txAmount = amount;
    snprintf((char *)tx->adSender, HASHLENGTH, "%s", sender);
    snprintf((char *)tx->adReceiver, HASHLENGTH, "%s", receiver);
    snprintf(tx->comment, MAX_STRING, "%s", comment);

    append_output(tx, receiver, amount, tx->timestamp);
    tx_compute_id(tx);

    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;
}

bool add_utxo_transaction_to_block(
    Block *b,
    Account wallets[MAX_USERS],
    int nb_users,
    const char *sender,
    const char *receiver,
    long amount,
    const char *comment,
    long *out_fee
) {
    if (b == NULL || sender == NULL || receiver == NULL || comment == NULL || amount <= 0) {
        return false;
    }
    if (b->nbTx >= MAXTX) {
        return false;
    }
    if (find_wallet_by_name(wallets, nb_users, sender) == -1 || find_wallet_by_name(wallets, nb_users, receiver) == -1) {
        return false;
    }
    if (strcmp(sender, receiver) == 0) {
        return false;
    }

    long fee = (amount * FEE_RATE) / 100;
    if (fee <= 0) {
        fee = 1;
    }
    long target = amount + fee;

    Utxo *selected[MAX_BUF];
    int selected_count = 0;
    long selected_sum = 0;

    Slist *node = g_utxo_pool;
    while (node != NULL && selected_sum < target && selected_count < MAX_BUF) {
        Utxo *candidate = (Utxo *)node->info;
        if (is_utxo_owned_by(candidate, sender)) {
            selected[selected_count++] = candidate;
            selected_sum += candidate->txOut->amount;
        }
        node = node->next;
    }

    if (selected_sum < target) {
        return false;
    }

    Transaction *tx = malloc(sizeof(Transaction));
    if (tx == NULL) {
        return false;
    }
    memset(tx, 0, sizeof(Transaction));

    tx->timestamp = time(NULL);
    tx->txAmount = amount;
    snprintf((char *)tx->adSender, HASHLENGTH, "%s", sender);
    snprintf((char *)tx->adReceiver, HASHLENGTH, "%s", receiver);
    snprintf(tx->comment, MAX_STRING, "%s", comment);

    for (int i = 0; i < selected_count; i++) {
        if (!append_input_reference(tx, selected[i])) {
            free(tx);
            return false;
        }
    }

    if (!append_output(tx, receiver, amount, tx->timestamp)) {
        free(tx);
        return false;
    }
    if (!append_output(tx, "FEE_POOL", fee, tx->timestamp)) {
        free(tx);
        return false;
    }

    long change = selected_sum - target;
    if (change > 0 && !append_output(tx, sender, change, tx->timestamp)) {
        free(tx);
        return false;
    }

    tx_compute_id(tx);
    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;

    if (out_fee != NULL) {
        *out_fee = fee;
    }
    return true;
}

void add_coinbase_transaction(Block *b, const char *miner_name, long reward, long fees_collected) {
    long coinbase_amount = reward + fees_collected;
    if (b == NULL || miner_name == NULL || coinbase_amount <= 0 || b->nbTx >= MAXTX) {
        return;
    }

    Transaction *tx = malloc(sizeof(Transaction));
    if (tx == NULL) {
        return;
    }
    memset(tx, 0, sizeof(Transaction));

    tx->timestamp = time(NULL);
    tx->txAmount = coinbase_amount;
    snprintf((char *)tx->adSender, HASHLENGTH, "%s", "Coinbase");
    snprintf((char *)tx->adReceiver, HASHLENGTH, "%s", miner_name);
    snprintf(tx->comment, MAX_STRING, "%s", "Coinbase reward");

    if (!append_output(tx, miner_name, coinbase_amount, tx->timestamp)) {
        free(tx);
        return;
    }

    tx_compute_id(tx);
    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;
}

void apply_block_utxo_effects(Block *b, Account wallets[MAX_USERS], int nb_users) {
    if (b == NULL) {
        return;
    }

    Slist *tx_node = b->transactions;
    while (tx_node != NULL) {
        Transaction *tx = (Transaction *)tx_node->info;

        Slist *in_node = tx->lstInputs;
        while (in_node != NULL) {
            Utxo *spent = (Utxo *)in_node->info;
            remove_utxo_from_pool(spent->hash, spent->indexOutput);
            in_node = in_node->next;
        }

        Slist *out_node = tx->lstOutputs;
        while (out_node != NULL) {
            TxOutputs *tx_out = (TxOutputs *)out_node->info;
            if (tx_out != NULL && tx_out->lockingScript[0] != NULL && strcmp(tx_out->lockingScript[0], "FEE_POOL") != 0) {
                TxOutputs *stored_out = clone_tx_output(tx_out);
                if (stored_out != NULL) {
                    Utxo *new_utxo = create_utxo(tx->txid, tx_out->outIndex, stored_out);
                    if (new_utxo != NULL) {
                        g_utxo_pool = Slist_add(g_utxo_pool, new_utxo);
                    } else {
                        free_tx_output(stored_out);
                    }
                }
            }
            out_node = out_node->next;
        }
        tx_node = tx_node->next;
    }

    recalculate_wallets_and_supply(wallets, nb_users);
}

void create_genesis_block(Blockchain *bc) {
    Block *genesis = create_empty_block(bc, "System");
    if (genesis == NULL) {
        printf("Memoire insuffisante pour creer genesis.\n");
        return;
    }

    genesis->index = 0;
    genesis->nonce = 0;
    snprintf((char *)genesis->previousHash, HASHLENGTH, "%s", "0");

    add_transaction_to_block(genesis, "Network", "Genesis", 0, "Initial Block");
    compute_merkle_root(genesis->transactions, genesis->nbTx, genesis->merkleTree);
    compute_block_hash(genesis, genesis->blockHash);

    bc->blocklist = Slist_add(bc->blocklist, genesis);
    bc->nbBlocks = 1;

    printf("Block Genesis cree et ajoute avec succes.\n");
}

void mine_and_add_block(Blockchain *bc, Block *new_block, Account wallets[MAX_USERS], int nb_users) {
    if (bc == NULL || new_block == NULL) {
        printf("Impossible de miner: blockchain ou bloc invalide.\n");
        return;
    }

    new_block->index = bc->nbBlocks;
    if (bc->blocklist != NULL) {
        Slist *previous_node = bc->blocklist;
        while (previous_node->next != NULL) {
            previous_node = previous_node->next;
        }
        Block *previous_block = (Block *)previous_node->info;
        snprintf((char *)new_block->previousHash, HASHLENGTH, "%s", previous_block->blockHash);
    } else {
        snprintf((char *)new_block->previousHash, HASHLENGTH, "%s", "0");
    }

    int id_miner = find_wallet_by_name(wallets, nb_users, new_block->minerName);
    new_block->miningReward = (id_miner != -1) ? bc->reward4mining : 0;

    printf("Recherche de la nonce pour le bloc %d (mining...)\n", new_block->index);
    mine_block(new_block, bc->difficulty);

    bc->blocklist = Slist_add(bc->blocklist, new_block);
    bc->nbBlocks++;

    apply_block_utxo_effects(new_block, wallets, nb_users);
}

void run_helicopter_money(Blockchain *bc, Account wallets[MAX_USERS], int nb_users) {
    printf("Distribution de %d BT a tout le monde...\n", HELIREWARD);

    Block *new_block = create_empty_block(bc, "Banque Centrale");
    if (new_block == NULL) {
        return;
    }

    for (int i = 0; i < nb_users; i++) {
        add_transaction_to_block(new_block, "Coinbase", wallets[i].str, HELIREWARD, "Distribution de depart");
    }

    mine_and_add_block(bc, new_block, wallets, nb_users);
    printf("Tout le monde a recu ses Bit-Thunes\n");
}

void process_market_round(Blockchain *bc, Account wallets[MAX_USERS], int nb_users, int random_tx_count) {
    if (bc == NULL || wallets == NULL || nb_users <= 1) {
        return;
    }

    int miner_idx = rand() % nb_users;
    Block *block = create_empty_block(bc, wallets[miner_idx].str);
    if (block == NULL) {
        return;
    }

    long fees_collected = 0;
    int generated = random_tx_count;
    int max_user_txs = MAXTX - 1;
    if (generated > max_user_txs) {
        generated = max_user_txs;
    }

    TxRequest fifo[MAXTX];
    for (int i = 0; i < generated; i++) {
        int sender = rand() % nb_users;
        int receiver = rand() % nb_users;
        while (receiver == sender) {
            receiver = rand() % nb_users;
        }

        snprintf(fifo[i].sender, MAX_STRING, "%s", wallets[sender].str);
        snprintf(fifo[i].receiver, MAX_STRING, "%s", wallets[receiver].str);
        fifo[i].amount = (rand() % 3000) + 1;
    }

    for (int i = 0; i < generated; i++) {
        long fee = 0;
        if (add_utxo_transaction_to_block(
                block,
                wallets,
                nb_users,
                fifo[i].sender,
                fifo[i].receiver,
                fifo[i].amount,
                "Market tx",
                &fee)) {
            fees_collected += fee;
        }
    }

    add_coinbase_transaction(block, block->minerName, g_current_reward, fees_collected);

    if (block->nbTx == 0) {
        free(block);
        return;
    }

    mine_and_add_block(bc, block, wallets, nb_users);

    printf(
        "[Market] cycle=%d block=%d miner=%s tx=%d reward=%ld fees=%ld supply=%ld\n",
        g_cycle_rounds,
        bc->nbBlocks - 1,
        block->minerName,
        block->nbTx,
        g_current_reward,
        fees_collected,
        g_money_supply);
}

long get_money_supply(void) {
    return g_money_supply;
}

long get_current_reward(void) {
    return g_current_reward;
}

int get_halving_count(void) {
    return g_halving_count;
}

int get_cycle_rounds(void) {
    return g_cycle_rounds;
}

void set_current_reward(long reward) {
    g_current_reward = (reward < 0) ? 0 : reward;
}

void increment_cycle_round(void) {
    g_cycle_rounds++;
}

void increment_halving_count(void) {
    g_halving_count++;
}
