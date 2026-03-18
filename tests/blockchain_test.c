#include "blockchain_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/blockchain_core.h"
#include "../src/blockchain_io.h"
#include "../src/blockchain_state.h"

#define AUTOTEST_JSON_PATH "build/json/autotest_chain.json"

static long compute_spent_in_block(Block *block, int user_idx, AppState *app) {
    long spent = 0;
    Slist *curr = block->transactions;
    while (curr != NULL) {
        Transaction *tx = (Transaction *)curr->info;
        if (tx != NULL) {
            int sender_idx = wallet_index_by_name(app, (const char *)tx->adSender);
            if (sender_idx == user_idx) {
                spent += tx->txAmount;
            }
        }
        curr = curr->next;
    }
    return spent;
}

static int fill_random_user_tx(AppState *app, Block *block, int user_tx_count) {
    int added = 0;
    int attempts = 0;
    int max_attempts = user_tx_count * 25;

    if (max_attempts < 25) {
        max_attempts = 25;
    }

    while (added < user_tx_count && attempts < max_attempts) {
        attempts++;
        int sender_idx = rand() % app->wallet_count;
        int receiver_idx = rand() % app->wallet_count;
        while (receiver_idx == sender_idx) {
            receiver_idx = rand() % app->wallet_count;
        }

        long sender_balance = app->wallets[sender_idx].balance;
        long spent_in_block = compute_spent_in_block(block, sender_idx, app);
        long available = sender_balance - spent_in_block;

        if (available <= 0) {
            continue;
        }

        long amount = (rand() % (int)available) + 1;
        block_add_tx(
            block,
            app->wallets[sender_idx].str,
            app->wallets[receiver_idx].str,
            amount,
            "autotest transfer"
        );
        added++;
    }

    return added;
}

static bool add_any_valid_transfer(AppState *app, Block *block) {
    for (int sender_idx = 0; sender_idx < app->wallet_count; sender_idx++) {
        long sender_balance = app->wallets[sender_idx].balance;
        long spent_in_block = compute_spent_in_block(block, sender_idx, app);
        long available = sender_balance - spent_in_block;

        if (available <= 0) {
            continue;
        }

        int receiver_idx = (sender_idx + 1) % app->wallet_count;
        long amount = (rand() % (int)available) + 1;

        block_add_tx(
            block,
            app->wallets[sender_idx].str,
            app->wallets[receiver_idx].str,
            amount,
            "autotest transfer"
        );
        return true;
    }

    return false;
}

static bool build_and_append_random_block(AppState *app, int tx_total_in_block) {
    Block *block = (Block *)calloc(1, sizeof(Block));
    if (!block) {
        return false;
    }

    Block *prev = get_block_at(app, app->chain.nbBlocks - 1);
    block->index = app->chain.nbBlocks;
    block->timestamp = time(NULL);
    if (prev != NULL) {
        strncpy((char *)block->previousHash, (char *)prev->blockHash, HASHLENGTH);
    } else {
        strncpy((char *)block->previousHash, "0", HASHLENGTH);
    }

    int miner_idx = rand() % app->wallet_count;
    strncpy(block->minerName, app->wallets[miner_idx].str, MAX_STRING);

    int user_tx_count = tx_total_in_block - 1;
    if (user_tx_count < 1) {
        user_tx_count = 1;
    }
    if (user_tx_count > (MAXTX - 1)) {
        user_tx_count = MAXTX - 1;
    }

    int added_user_tx = fill_random_user_tx(app, block, user_tx_count);
    if (added_user_tx == 0 && !add_any_valid_transfer(app, block)) {
        free(block);
        return false;
    }

    block_add_tx(block, COINBASE_NAME, block->minerName, app->chain.reward4mining, "mining reward");

    if (!append_mined_block(app, block)) {
        free(block);
        return false;
    }

    return true;
}

void run_autotest(AppState *app) {
    unsigned int old_seed = (unsigned int)time(NULL);
    srand(42);

    create_blockchain_with_users(app, MAX_USERS);
    int before_heli_blocks = app->chain.nbBlocks;
    bool ok = run_helicopter_money_internal(app);
    int heli_blocks = app->chain.nbBlocks - before_heli_blocks;

    int blocks_to_generate = (rand() % 10) + 1;
    int generated_ok_blocks = 0;
    for (int b = 0; b < blocks_to_generate && ok; b++) {
        int tx_total = (rand() % 10) + 1;
        ok = build_and_append_random_block(app, tx_total);
        if (ok) {
            generated_ok_blocks++;
        }
    }

    ok = ok && verify_chain_integrity(app);

    long expected_supply = (MAX_USERS * HELICOPTER_AMOUNT) + ((long)(heli_blocks + generated_ok_blocks) * app->chain.reward4mining);
    long actual_supply = total_supply(app);
    ok = ok && (actual_supply == expected_supply);

    if (ok) {
        if (!write_blockchain_json_file(app, AUTOTEST_JSON_PATH)) {
            ok = false;
        }
    }

    printf("\n[Autotest] integrity=%s supply=%ld expected=%ld\n", verify_chain_integrity(app) ? "OK" : "FAIL", actual_supply, expected_supply);
    printf("[Autotest] generated_blocks=%d/%d (requested up to 10)\n", generated_ok_blocks, blocks_to_generate);
    printf("[Autotest] json_export=%s\n", ok ? "OK (build/json/autotest_chain.json)" : "FAIL");

    srand(old_seed);
}