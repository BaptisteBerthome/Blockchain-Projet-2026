#include "blockchain_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blockchain_core.h"
#include "blockchain_io.h"

static Slist *list_push_back(Slist **head, void *info) {
    Slist *node = (Slist *)malloc(sizeof(Slist));
    if (!node) {
        return NULL;
    }
    node->info = info;
    node->next = NULL;
    if (*head == NULL) {
        *head = node;
        return node;
    }
    Slist *cur = *head;
    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = node;
    return node;
}

static Block *last_block(const AppState *app) {
    if (app->chain.blocklist == NULL) {
        return NULL;
    }
    Slist *cur = app->chain.blocklist;
    while (cur->next != NULL) {
        cur = cur->next;
    }
    return (Block *)cur->info;
}

static void free_transaction_list(Slist *tx_list) {
    Slist *node = tx_list;
    while (node != NULL) {
        Slist *next = node->next;
        free(node->info);
        free(node);
        node = next;
    }
}

static void free_block_list(Slist *block_list) {
    Slist *node = block_list;
    while (node != NULL) {
        Slist *next = node->next;
        Block *block = (Block *)node->info;
        if (block != NULL) {
            free_transaction_list(block->transactions);
            free(block);
        }
        free(node);
        node = next;
    }
}

void init_wallets(AppState *app, int users) {
    app->wallet_count = users;
    for (int i = 0; i < users; i++) {
        memset(&app->wallets[i], 0, sizeof(Account));
        snprintf(app->wallets[i].str, MAX_STRING, "user%d", i + 1);
        app->wallets[i].balance = 0;
    }
}

int wallet_index_by_name(const AppState *app, const char *name) {
    for (int i = 0; i < app->wallet_count; i++) {
        if (strcmp(app->wallets[i].str, name) == 0) {
            return i;
        }
    }
    return -1;
}

int random_miner_index(const AppState *app) {
    (void)app;
    return rand() % app->wallet_count;
}

void apply_transaction(AppState *app, const Transaction *tx) {
    if (strcmp((char *)tx->adSender, COINBASE_NAME) != 0) {
        int from = wallet_index_by_name(app, (char *)tx->adSender);
        if (from >= 0) {
            app->wallets[from].balance -= tx->txAmount;
        }
    }

    int to = wallet_index_by_name(app, (char *)tx->adReceiver);
    if (to >= 0) {
        app->wallets[to].balance += tx->txAmount;
    }
}

long total_supply(const AppState *app) {
    long sum = 0;
    for (int i = 0; i < app->wallet_count; i++) {
        sum += app->wallets[i].balance;
    }
    return sum;
}

void block_add_tx(Block *block, const char *sender, const char *receiver, long amount, const char *comment) {
    if (block->nbTx >= MAXTX) {
        return;
    }

    Transaction *tx = (Transaction *)calloc(1, sizeof(Transaction));
    if (!tx) {
        return;
    }
    tx->timestamp = time(NULL);
    strncpy((char *)tx->adSender, sender, HASHLENGTH);
    tx->adSender[HASHLENGTH - 1] = '\0';
    strncpy((char *)tx->adReceiver, receiver, HASHLENGTH);
    tx->adReceiver[HASHLENGTH - 1] = '\0';
    tx->txAmount = amount;
    strncpy(tx->comment, comment, MAX_STRING);
    tx->comment[MAX_STRING - 1] = '\0';
    tx_compute_id(tx);
    if (!list_push_back(&block->transactions, tx)) {
        free(tx);
        return;
    }
    block->nbTx++;
}

void create_genesis(AppState *app) {
    Blockchain *bc = &app->chain;
    Block *genesis = (Block *)calloc(1, sizeof(Block));
    if (!genesis) {
        return;
    }

    genesis->index = 0;
    strncpy((char *)genesis->previousHash, "0", HASHLENGTH);
    genesis->timestamp = time(NULL);
    strncpy(genesis->minerName, COINBASE_NAME, MAX_STRING);
    genesis->nonce = 0;

    block_add_tx(genesis, COINBASE_NAME, "genesis", 0, "Genesis block");
    compute_merkle_root(genesis->transactions, genesis->nbTx, (char *)genesis->merkleTree);
    compute_block_hash(genesis, (char *)genesis->blockHash);

    if (!list_push_back(&bc->blocklist, genesis)) {
        free(genesis);
        return;
    }
    bc->nbBlocks = 1;
}

bool append_mined_block(AppState *app, Block *block) {
    Blockchain *bc = &app->chain;
    if (bc->nbBlocks >= MAX_BLOCK) {
        printf("Blockchain is full.\n");
        return false;
    }

    mine_block(block, bc->difficulty);

    if (!list_push_back(&bc->blocklist, block)) {
        return false;
    }
    bc->nbBlocks++;

    for (Slist *node = block->transactions; node != NULL; node = node->next) {
        Transaction *tx = (Transaction *)node->info;
        apply_transaction(app, tx);
    }
    return true;
}

void create_blockchain_with_users(AppState *app, int users) {
    free_blockchain_memory(app);
    memset(app, 0, sizeof(*app));
    app->chain.difficulty = DIFFICULTY;
    app->chain.reward4mining = INITIALREWARD;
    app->pending_block = NULL;
    init_wallets(app, users);
    create_genesis(app);
    app->initialized = true;
}

bool create_user_transaction_by_name(AppState *app, const char *sender, const char *receiver, long amount) {
    if (!app->initialized) {
        printf("Create blockchain first.\n");
        return false;
    }

    int from = wallet_index_by_name(app, sender);
    int to = wallet_index_by_name(app, receiver);
    if (from < 0 || to < 0) {
        printf("Unknown emitter or receiver.\n");
        return false;
    }
    if (app->wallets[from].balance < amount) {
        printf("Insufficient funds for %s. Balance: %ld BT\n", sender, app->wallets[from].balance);
        return false;
    }

    if (app->pending_block == NULL) {
        app->pending_block = (Block *)calloc(1, sizeof(Block));
        if (!app->pending_block) {
            printf("Failed to allocate pending block.\n");
            return false;
        }
        Block *prev = last_block(app);
        app->pending_block->index = app->chain.nbBlocks;
        app->pending_block->timestamp = time(NULL);
        if (prev != NULL) {
            strncpy((char *)app->pending_block->previousHash, (char *)prev->blockHash, HASHLENGTH);
        } else {
            strncpy((char *)app->pending_block->previousHash, "0", HASHLENGTH);
        }
        int miner_idx = random_miner_index(app);
        strncpy(app->pending_block->minerName, app->wallets[miner_idx].str, MAX_STRING);
    }

    block_add_tx(app->pending_block, sender, receiver, amount, "simple transfer");
    
    int tx_count = 0;
    for (Slist *node = app->pending_block->transactions; node != NULL; node = node->next) {
        Transaction *tx = (Transaction *)node->info;
        if (strcmp((char *)tx->adSender, COINBASE_NAME) != 0) {
            tx_count++;
        }
    }

    printf("Transaction added to pending block. Pending block: %d / %d (max user transactions)\n", tx_count, MAXTX - 1);

    if (tx_count >= MAXTX - 1) {
        printf("Pending block full. Auto-mining...\n");
        return mine_pending_block(app);
    }

    return true;
}

bool mine_pending_block(AppState *app) {
    if (!app->initialized) {
        printf("Create blockchain first.\n");
        return false;
    }

    if (app->pending_block == NULL) {
        printf("No pending block to mine.\n");
        return false;
    }

    block_add_tx(app->pending_block, COINBASE_NAME, app->pending_block->minerName, app->chain.reward4mining, "mining reward");

    if (!append_mined_block(app, app->pending_block)) {
        free(app->pending_block);
        app->pending_block = NULL;
        return false;
    }

    printf("Block %d mined by %s, nonce=%ld\n", app->pending_block->index, app->pending_block->minerName, app->pending_block->nonce);
    print_block_json(stdout, app->pending_block);
    printf("\n");
    print_wallets(app);

    app->pending_block = NULL;
    return true;
}

bool run_helicopter_money_internal(AppState *app) {
    if (!app->initialized) {
        printf("Create blockchain first.\n");
        return false;
    }

    int grants_per_block = MAXTX - 1;
    int created_blocks = 0;

    for (int start = 0; start < app->wallet_count; start += grants_per_block) {
        int miner_idx = random_miner_index(app);
        Block *block = (Block *)calloc(1, sizeof(Block));
        if (!block) {
            return false;
        }
        Block *prev = last_block(app);

        block->index = app->chain.nbBlocks;
        block->timestamp = time(NULL);
        if (prev != NULL) {
            strncpy((char *)block->previousHash, (char *)prev->blockHash, HASHLENGTH);
        } else {
            strncpy((char *)block->previousHash, "0", HASHLENGTH);
        }
        strncpy(block->minerName, app->wallets[miner_idx].str, MAX_STRING);

        int end = start + grants_per_block;
        if (end > app->wallet_count) {
            end = app->wallet_count;
        }
        for (int i = start; i < end; i++) {
            block_add_tx(block, COINBASE_NAME, app->wallets[i].str, HELICOPTER_AMOUNT, "helicopter money");
        }
        block_add_tx(block, COINBASE_NAME, block->minerName, app->chain.reward4mining, "mining reward");

        if (!append_mined_block(app, block)) {
            free(block);
            return false;
        }
        created_blocks++;
        printf("Helicopter block %d mined by %s.\n", block->index, block->minerName);
    }

    printf("Helicopter money executed in %d block(s).\n", created_blocks);
    printf("Total monetary supply: %ld BT\n", total_supply(app));
    return true;
}

Block *get_block_at(const AppState *app, int index) {
    int i = 0;
    for (Slist *node = app->chain.blocklist; node != NULL; node = node->next) {
        if (i == index) {
            return (Block *)node->info;
        }
        i++;
    }
    return NULL;
}

void free_blockchain_memory(AppState *app) {
    if (app == NULL) {
        return;
    }

    free_block_list(app->chain.blocklist);
    app->chain.blocklist = NULL;
    app->chain.nbBlocks = 0;
    
    if (app->pending_block != NULL) {
        free_transaction_list(app->pending_block->transactions);
        free(app->pending_block);
        app->pending_block = NULL;
    }
    
    app->initialized = false;
}
