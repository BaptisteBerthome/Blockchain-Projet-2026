#include "../include/blockchain_state.h"

#include "../include/blockchain_core.h"
#include "../include/utils.h"
#include "../include/crypto.h"  // partie 3 : cles / adresses / signatures
#include "../include/script.h"  // partie 3 : interpreteur de scripts
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

#define FEE_POOL_LABEL "FEE_POOL"

// =====================================================================
//  Helpers comptes / adresses
// =====================================================================
void wallet_pubkeyhash(const Account *w, char *out) {
    crypto_hash160((const char *)w->pub_key, out);
}

int find_wallet_by_name(Account wallets[MAX_USERS], int nb_users, const char *name) {
    for (int i = 0; i < nb_users; i++) {
        if (strcmp(wallets[i].str, name) == 0) {
            return i;
        }
    }
    return -1;
}

int find_wallet_by_address(Account wallets[MAX_USERS], int nb_users, const char *address) {
    for (int i = 0; i < nb_users; i++) {
        if (strcmp((const char *)wallets[i].address, address) == 0) {
            return i;
        }
    }
    return -1;
}

int resolve_account(Account wallets[MAX_USERS], int nb_users, const char *id) {
    int idx = find_wallet_by_address(wallets, nb_users, id);
    if (idx == -1) {
        idx = find_wallet_by_name(wallets, nb_users, id);
    }
    return idx;
}

// Cherche le compte proprietaire d'un H(pubKey) donne (identite d'adresse).
static int find_wallet_by_pubkeyhash(Account wallets[MAX_USERS], int nb_users, const char *pkh) {
    char h[HASH160_HEX_LEN];
    for (int i = 0; i < nb_users; i++) {
        wallet_pubkeyhash(&wallets[i], h);
        if (strcmp(h, pkh) == 0) {
            return i;
        }
    }
    return -1;
}

// =====================================================================
//  Helpers outputs (scriptPubKey P2PKH par adresse)
// =====================================================================
static TxOutputs *create_tx_output(long amount, time_t ts) {
    TxOutputs *out = malloc(sizeof(TxOutputs));
    if (out == NULL) {
        return NULL;
    }
    memset(out, 0, sizeof(TxOutputs));
    out->amount = amount;
    out->timestamp = ts;
    return out;
}

static void free_tx_output(TxOutputs *out) {
    if (out == NULL) {
        return;
    }
    for (int i = 0; i < SCRIPTPUBKEY_SIZE; i++) {
        free(out->lockingScript[i]);
    }
    free(out);
}

static TxOutputs *clone_tx_output(const TxOutputs *src) {
    if (src == NULL) {
        return NULL;
    }
    TxOutputs *copy = create_tx_output(src->amount, src->timestamp);
    if (copy == NULL) {
        return NULL;
    }
    copy->outIndex = src->outIndex;
    memcpy(copy->pubKeyHash, src->pubKeyHash, HASHLENGTH);
    memcpy(copy->ownerAddress, src->ownerAddress, ADDRESS_STR_LEN);
    for (int i = 0; i < SCRIPTPUBKEY_SIZE; i++) {
        if (src->lockingScript[i] != NULL) {
            size_t n = strlen(src->lockingScript[i]) + 1;
            copy->lockingScript[i] = malloc(n);
            if (copy->lockingScript[i] != NULL) {
                memcpy(copy->lockingScript[i], src->lockingScript[i], n);
            }
        }
    }
    return copy;
}

// Cree un output verrouille a un proprietaire.
// 'owner_id' = adresse ou mnemonique d'un compte, ou sentinelle (FEE_POOL).
static bool append_output(Transaction *tx, Account *wallets, int nb_users,
                          const char *owner_id, long amount, time_t ts) {
    TxOutputs *out = create_tx_output(amount, ts);
    if (out == NULL) {
        return false;
    }
    out->outIndex = tx->nbOutputs;

    int idx = (wallets != NULL) ? resolve_account(wallets, nb_users, owner_id) : -1;
    if (idx != -1) {
        // output verrouille par adresse : scriptPubKey P2PKH complet
        snprintf((char *)out->ownerAddress, ADDRESS_STR_LEN, "%.*s", ADDRESS_STR_LEN - 1, wallets[idx].address);
        wallet_pubkeyhash(&wallets[idx], (char *)out->pubKeyHash);
        script_build_scriptpubkey(out->lockingScript, (const char *)out->pubKeyHash);
    } else {
        // sentinelle (FEE_POOL, Genesis...) : pas de script, jamais depensable
        snprintf((char *)out->ownerAddress, ADDRESS_STR_LEN, "%.*s", ADDRESS_STR_LEN - 1, owner_id);
        out->pubKeyHash[0] = '\0';
    }

    tx->lstOutputs = Slist_add(tx->lstOutputs, out);
    tx->nbOutputs++;
    return true;
}

// =====================================================================
//  Helpers UTXO pool
// =====================================================================
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
        if (utxo != NULL && utxo->txOut != NULL && utxo->txOut->pubKeyHash[0] != '\0') {
            int idx = find_wallet_by_pubkeyhash(wallets, nb_users, (const char *)utxo->txOut->pubKeyHash);
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

// Applique IMMEDIATEMENT les effets d'une tx sur le pool d'UTXO :
//   - retire les UTXO depenses (inputs)
//   - ajoute les nouveaux UTXO (outputs verrouilles par adresse)
// Appele des qu'une tx est finalisee : evite qu'une 2e tx du meme bloc
// reselectionne un UTXO deja depense (double-spend dans un meme bloc).
static void commit_tx_to_pool(Transaction *tx) {
    Slist *in_node = tx->lstInputs;
    while (in_node != NULL) {
        Utxo *spent = (Utxo *)in_node->info;
        remove_utxo_from_pool(spent->hash, spent->indexOutput);
        in_node = in_node->next;
    }

    Slist *out_node = tx->lstOutputs;
    while (out_node != NULL) {
        TxOutputs *tx_out = (TxOutputs *)out_node->info;
        if (tx_out != NULL && tx_out->pubKeyHash[0] != '\0') {
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
}

static bool utxo_owned_by_pkh(const Utxo *utxo, const char *pkh) {
    return utxo != NULL && utxo->txOut != NULL && utxo->txOut->pubKeyHash[0] != '\0' &&
           strcmp((const char *)utxo->txOut->pubKeyHash, pkh) == 0;
}

// Partie 3/4 : reference d'input + scriptSig (signe 'message' = txid).
static Utxo *append_input_reference(Transaction *tx, const Utxo *source,
                                    Account *spender, const char *message) {
    Utxo *input_ref = malloc(sizeof(Utxo));
    if (input_ref == NULL) {
        return NULL;
    }
    memset(input_ref, 0, sizeof(Utxo));
    snprintf((char *)input_ref->hash, HASHLENGTH, "%s", source->hash);
    input_ref->indexOutput = source->indexOutput;

    // champs explicites (partie 4) : signature + cle publique
    crypto_sign((const char *)spender->priv_key, message, (char *)input_ref->signature);
    snprintf((char *)input_ref->pubKey, PUBKEY_HEX_LEN, "%s", (const char *)spender->pub_key);
    // scriptSig <sig> <pubKey>
    script_build_scriptsig(input_ref->scriptSig,
                           (const char *)input_ref->signature,
                           (const char *)input_ref->pubKey);

    tx->lstInputs = Slist_add(tx->lstInputs, input_ref);
    tx->nbInputs++;
    return input_ref;
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
        memset(&wallets[i], 0, sizeof(Account));
        snprintf(wallets[i].str, MAX_STRING, "user%d", i + 1);
        wallets[i].balance = 0;
        wallets[i].utxoList = NULL;
        // Partie 3 : generation des cles et de l'adresse P2PKH
        crypto_generate_keypair((char *)wallets[i].priv_key,
                                (char *)wallets[i].pub_key,
                                (char *)wallets[i].address);
    }
    printf("%d utilisateurs crees (user1 a user%d) avec cles + adresses.\n", nb_users, nb_users);
}

void reset_utxo_state(void) {
    clear_utxo_pool();
    g_money_supply = 0;
    g_current_reward = INITIALREWARD;
    g_halving_count = 0;
    g_cycle_rounds = 0;
}

void add_transaction_to_block(Block *b, Account wallets[MAX_USERS], int nb_users,
                              const char *sender, const char *receiver, long amount, const char *comment) {
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

    append_output(tx, wallets, nb_users, receiver, amount, tx->timestamp);
    tx_compute_id(tx);

    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;
    commit_tx_to_pool(tx);
}

bool add_utxo_transaction_to_block(
    Block *b,
    Account wallets[MAX_USERS],
    int nb_users,
    const char *sender,
    const char *receiver,
    long amount,
    const char *comment,
    long *out_fee,
    bool verbose
) {
    if (b == NULL || sender == NULL || receiver == NULL || comment == NULL || amount <= 0) {
        return false;
    }
    if (b->nbTx >= MAXTX) {
        return false;
    }
    int sender_idx = resolve_account(wallets, nb_users, sender);
    int receiver_idx = resolve_account(wallets, nb_users, receiver);
    if (sender_idx == -1 || receiver_idx == -1) {
        return false;
    }
    if (sender_idx == receiver_idx) {
        return false;
    }

    // adresses canoniques
    const char *sender_addr = (const char *)wallets[sender_idx].address;
    const char *receiver_addr = (const char *)wallets[receiver_idx].address;
    char sender_pkh[HASH160_HEX_LEN];
    wallet_pubkeyhash(&wallets[sender_idx], sender_pkh);

    long fee = (amount * FEE_RATE) / 100;
    if (fee <= 0) {
        fee = 1;
    }
    long target = amount + fee;

    // --- selection greedy des UTXO du sender (par H(pubKey)) ---
    Utxo *selected[MAX_BUF];
    int selected_count = 0;
    long selected_sum = 0;

    Slist *node = g_utxo_pool;
    while (node != NULL && selected_sum < target && selected_count < MAX_BUF) {
        Utxo *candidate = (Utxo *)node->info;
        if (utxo_owned_by_pkh(candidate, sender_pkh)) {
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
    snprintf((char *)tx->adSender, HASHLENGTH, "%s", sender_addr);
    snprintf((char *)tx->adReceiver, HASHLENGTH, "%s", receiver_addr);
    snprintf(tx->comment, MAX_STRING, "%s", comment);

    // txid calcule tot : il sert de message a signer (independant des scripts)
    tx_compute_id(tx);
    ScriptContext ctx = { .message = (const char *)tx->txid };

    // --- inputs : on signe et on VERIFIE le script de chaque UTXO depense ---
    for (int i = 0; i < selected_count; i++) {
        Utxo *input_ref = append_input_reference(tx, selected[i], &wallets[sender_idx],
                                                 (const char *)tx->txid);
        if (input_ref == NULL) {
            free(tx);
            return false;
        }
        if (verbose) {
            printf("    [input %d] verification de la depense (scriptSig + scriptPubKey de l'UTXO) :\n", i);
        }
        // scriptSig (input) ++ scriptPubKey (output depense)
        if (!script_execute(input_ref->scriptSig, selected[i]->txOut->lockingScript, &ctx, verbose)) {
            printf("    [SECURITE] script invalide : depense illegitime rejetee.\n");
            free(tx);
            return false;
        }
    }

    // --- outputs : destinataire + commission + monnaie rendue ---
    if (!append_output(tx, wallets, nb_users, receiver_addr, amount, tx->timestamp)) {
        free(tx);
        return false;
    }
    if (!append_output(tx, wallets, nb_users, FEE_POOL_LABEL, fee, tx->timestamp)) {
        free(tx);
        return false;
    }

    long change = selected_sum - target;
    if (change > 0 && !append_output(tx, wallets, nb_users, sender_addr, change, tx->timestamp)) {
        free(tx);
        return false;
    }

    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;
    commit_tx_to_pool(tx); // met a jour le pool tout de suite (anti double-spend intra-bloc)

    if (out_fee != NULL) {
        *out_fee = fee;
    }
    return true;
}

void add_coinbase_transaction(Block *b, Account wallets[MAX_USERS], int nb_users,
                              const char *miner_name, long reward, long fees_collected) {
    long coinbase_amount = reward + fees_collected;
    if (b == NULL || miner_name == NULL || coinbase_amount <= 0 || b->nbTx >= MAXTX) {
        return;
    }

    int idx = resolve_account(wallets, nb_users, miner_name);
    const char *miner_addr = (idx != -1) ? (const char *)wallets[idx].address : miner_name;

    Transaction *tx = malloc(sizeof(Transaction));
    if (tx == NULL) {
        return;
    }
    memset(tx, 0, sizeof(Transaction));

    tx->timestamp = time(NULL);
    tx->txAmount = coinbase_amount;
    snprintf((char *)tx->adSender, HASHLENGTH, "%s", "Coinbase");
    snprintf((char *)tx->adReceiver, HASHLENGTH, "%s", miner_addr);
    snprintf(tx->comment, MAX_STRING, "%s", "Coinbase reward");

    if (!append_output(tx, wallets, nb_users, miner_addr, coinbase_amount, tx->timestamp)) {
        free(tx);
        return;
    }

    tx_compute_id(tx);
    b->transactions = Slist_add(b->transactions, tx);
    b->nbTx++;
    commit_tx_to_pool(tx);
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

    add_transaction_to_block(genesis, NULL, 0, "Network", "Genesis", 0, "Initial Block");
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

    // le pool a deja ete mis a jour tx par tx (commit_tx_to_pool) :
    // ici on se contente de recalculer les soldes / la masse monetaire.
    recalculate_wallets_and_supply(wallets, nb_users);
}

void run_helicopter_money(Blockchain *bc, Account wallets[MAX_USERS], int nb_users) {
    printf("Distribution de %d BT a tout le monde...\n", HELIREWARD);

    Block *new_block = create_empty_block(bc, "Banque Centrale");
    if (new_block == NULL) {
        return;
    }

    for (int i = 0; i < nb_users; i++) {
        add_transaction_to_block(new_block, wallets, nb_users, "Coinbase",
                                 (const char *)wallets[i].address, HELIREWARD, "Distribution de depart");
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

        snprintf(fifo[i].sender, MAX_STRING, "%.*s", MAX_STRING - 1, (const char *)wallets[sender].address);
        snprintf(fifo[i].receiver, MAX_STRING, "%.*s", MAX_STRING - 1, (const char *)wallets[receiver].address);
        fifo[i].amount = (rand() % MARKET_MAX_TX_AMOUNT) + 1;
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
                &fee,
                false)) {
            fees_collected += fee;
        }
    }

    add_coinbase_transaction(block, wallets, nb_users, block->minerName, g_current_reward, fees_collected);

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

// =====================================================================
//  CC4 : analyse de la blockchain pour reconstruire un wallet par adresse
// =====================================================================
static bool input_spends(Blockchain *bc, const BYTE *txid, int out_index) {
    Slist *bn = bc->blocklist;
    while (bn != NULL) {
        Block *blk = (Block *)bn->info;
        Slist *tn = blk->transactions;
        while (tn != NULL) {
            Transaction *tx = (Transaction *)tn->info;
            Slist *in = tx->lstInputs;
            while (in != NULL) {
                Utxo *u = (Utxo *)in->info;
                if (strcmp((const char *)u->hash, (const char *)txid) == 0 && u->indexOutput == out_index) {
                    return true;
                }
                in = in->next;
            }
            tn = tn->next;
        }
        bn = bn->next;
    }
    return false;
}

void analyze_blockchain_for_address(Blockchain *bc, Account wallets[MAX_USERS],
                                    int nb_users, const char *address_or_name) {
    if (bc == NULL || address_or_name == NULL) {
        return;
    }

    // Resolution : adresse, mnemonique, ou directement un H(pubKey).
    char target_hash[HASH160_HEX_LEN] = {0};
    const char *label = address_or_name;
    int idx = resolve_account(wallets, nb_users, address_or_name);
    if (idx != -1) {
        wallet_pubkeyhash(&wallets[idx], target_hash);
        label = (const char *)wallets[idx].address;
    } else {
        snprintf(target_hash, sizeof(target_hash), "%s", address_or_name);
    }

    printf("\n=== ANALYSE BLOCKCHAIN POUR : %s (H(pubKey)=%s) ===\n", label, target_hash);

    long balance = 0;
    int utxo_count = 0;
    Slist *bn = bc->blocklist;
    while (bn != NULL) {
        Block *blk = (Block *)bn->info;
        Slist *tn = blk->transactions;
        while (tn != NULL) {
            Transaction *tx = (Transaction *)tn->info;
            Slist *on = tx->lstOutputs;
            while (on != NULL) {
                TxOutputs *o = (TxOutputs *)on->info;
                if (o != NULL && o->pubKeyHash[0] != '\0' &&
                    strcmp((const char *)o->pubKeyHash, target_hash) == 0) {
                    if (!input_spends(bc, tx->txid, o->outIndex)) {
                        balance += o->amount;
                        utxo_count++;
                        printf("  UTXO bloc=%d txid=%.12s.. index=%d montant=%ld BT\n",
                               blk->index, tx->txid, o->outIndex, o->amount);
                    }
                }
                on = on->next;
            }
            tn = tn->next;
        }
        bn = bn->next;
    }

    printf("  -> %d UTXO non depenses, solde reconstruit = %ld BT\n", utxo_count, balance);
    printf("==================================================\n");
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
