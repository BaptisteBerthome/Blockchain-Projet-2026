#include "blockchain_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hash_text(const char *text, char out_hash[HASHLENGTH]) {
    sha256ofString((BYTE *)text, out_hash);
    out_hash[HASHLENGTH - 1] = '\0';
}

void tx_compute_id(Transaction *tx) {
    char buf[512];
    snprintf(
        buf,
        sizeof(buf),
        "%ld|%s|%s|%ld|%s",
        (long)tx->timestamp,
        tx->adSender,
        tx->adReceiver,
        tx->txAmount,
        tx->comment
    );
    hash_text(buf, (char *)tx->txid);
}

bool starts_with_zeros(const char *hex_hash, int zeros) {
    for (int i = 0; i < zeros; i++) {
        if (hex_hash[i] != '0') {
            return false;
        }
    }
    return true;
}

void compute_merkle_root(const Slist *tx_list, int tx_count, char out_root[HASHLENGTH]) {
    if (tx_count <= 0) {
        hash_text("", out_root);
        return;
    }

    char level[MAXTX][HASHLENGTH];
    int count = tx_count;
    int idx = 0;

    for (const Slist *node = tx_list; node != NULL && idx < tx_count; node = node->next) {
        Transaction *tx = (Transaction *)node->info;
        strncpy(level[idx], (char *)tx->txid, HASHLENGTH);
        level[idx][HASHLENGTH - 1] = '\0';
        idx++;
    }

    if (idx == 0) {
        hash_text("", out_root);
        return;
    }
    count = idx;

    while (count > 1) {
        char next_level[MAXTX][HASHLENGTH];
        int next_count = 0;

        for (int i = 0; i < count; i += 2) {
            const char *left = level[i];
            const char *right = (i + 1 < count) ? level[i + 1] : level[i];
            char pair[(SHA256_BLOCK_SIZE * 2 + 1) * 2];
            snprintf(pair, sizeof(pair), "%s%s", left, right);
            hash_text(pair, next_level[next_count]);
            next_count++;
        }

        for (int i = 0; i < next_count; i++) {
            strncpy(level[i], next_level[i], HASHLENGTH);
            level[i][HASHLENGTH - 1] = '\0';
        }
        count = next_count;
    }

    strncpy(out_root, level[0], HASHLENGTH);
    out_root[HASHLENGTH - 1] = '\0';
}

void compute_block_hash(const Block *block, char out_hash[HASHLENGTH]) {
    char payload[1024];
    snprintf(
        payload,
        sizeof(payload),
        "%d|%s|%ld|%s|%s|%ld|%d",
        block->index,
        block->previousHash,
        (long)block->timestamp,
        block->merkleTree,
        block->minerName,
        block->nonce,
        block->nbTx
    );
    hash_text(payload, out_hash);
}

void mine_block(Block *block, int difficulty) {
    compute_merkle_root(block->transactions, block->nbTx, (char *)block->merkleTree);
    block->nonce = 0;
    while (1) {
        compute_block_hash(block, (char *)block->blockHash);
        if (starts_with_zeros((char *)block->blockHash, difficulty)) {
            return;
        }
        block->nonce++;
    }
}

bool verify_chain_integrity(const AppState *app) {
    const Blockchain *bc = &app->chain;
    const Slist *node = bc->blocklist;
    const Block *prev = NULL;
    int idx = 0;

    while (node != NULL) {
        const Block *block = (const Block *)node->info;

        char expected_merkle[HASHLENGTH];
        compute_merkle_root(block->transactions, block->nbTx, expected_merkle);
        if (strcmp(expected_merkle, (char *)block->merkleTree) != 0) {
            printf("Integrity error at block %d: invalid Merkle root.\n", idx);
            return false;
        }

        char expected_hash[HASHLENGTH];
        compute_block_hash(block, expected_hash);
        if (strcmp(expected_hash, (char *)block->blockHash) != 0) {
            printf("Integrity error at block %d: invalid block hash.\n", idx);
            return false;
        }

        if (idx > 0) {
            if (strcmp((char *)block->previousHash, (char *)prev->blockHash) != 0) {
                printf("Integrity error at block %d: previous hash mismatch.\n", idx);
                return false;
            }
            if (!starts_with_zeros((char *)block->blockHash, bc->difficulty)) {
                printf("Integrity error at block %d: difficulty mismatch.\n", idx);
                return false;
            }
        }

        prev = block;
        node = node->next;
        idx++;
    }

    return true;
}
