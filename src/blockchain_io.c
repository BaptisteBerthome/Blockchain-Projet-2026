#include "blockchain_io.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "blockchain_state.h"

static void format_timestamp_string(time_t ts, char *out, size_t out_size) {
    const char *raw = ctime(&ts);
    if (raw == NULL) {
        snprintf(out, out_size, "unknown");
        return;
    }

    snprintf(out, out_size, "%s", raw);
    size_t len = strlen(out);
    if (len > 0 && out[len - 1] == '\n') {
        out[len - 1] = '\0';
    }
}

static void print_tx_json(FILE *out, const Transaction *tx, int indent) {
    char ts_str[64];
    const char *tab = (indent == 2) ? "    " : "      ";
    format_timestamp_string((time_t)tx->timestamp, ts_str, sizeof(ts_str));

    fprintf(out, "%s{\n", tab);
    fprintf(out, "%s  \"TxId\": \"%s\",\n", tab, (char *)tx->txid);
    fprintf(out, "%s  \"Timestamp\": \"%s\",\n", tab, ts_str);
    fprintf(out, "%s  \"Sender\": \"%s\",\n", tab, (char *)tx->adSender);
    fprintf(out, "%s  \"Receiver\": \"%s\",\n", tab, (char *)tx->adReceiver);
    fprintf(out, "%s  \"Amount\": %ld,\n", tab, tx->txAmount);
    fprintf(out, "%s  \"Nb inputs\": 0,\n", tab);
    fprintf(out, "%s  \"Inputs list\": [],\n", tab);
    fprintf(out, "%s  \"Nb outputs\": 0,\n", tab);
    fprintf(out, "%s  \"Outputs list\": [],\n", tab);
    fprintf(out, "%s  \"Comments\": \"%s\"\n", tab, tx->comment);
    fprintf(out, "%s}", tab);
}

void print_block_json(FILE *out, const Block *block) {
    char ts_str[64];
    format_timestamp_string((time_t)block->timestamp, ts_str, sizeof(ts_str));

    fprintf(out, "{\n");
    fprintf(out, "  \"index\": %d,\n", block->index);
    fprintf(out, "  \"time stamp\": \"%s\",\n", ts_str);
    fprintf(out, "  \"previous hash\": \"%s\",\n", (char *)block->previousHash);
    fprintf(out, "  \"Nb tx\": %d,\n", block->nbTx);
    fprintf(out, "  \"transactions\": [\n");

    int tx_i = 0;
    for (Slist *node = block->transactions; node != NULL; node = node->next) {
        Transaction *tx = (Transaction *)node->info;
        print_tx_json(out, tx, 2);
        tx_i++;
        if (tx_i < block->nbTx) {
            fprintf(out, ",");
        }
        fprintf(out, "\n");
    }

    fprintf(out, "  ],\n");
    fprintf(out, "  \"Merkle root\": \"%s\",\n", (char *)block->merkleTree);
    fprintf(out, "  \"current hash\": \"%s\",\n", (char *)block->blockHash);
    fprintf(out, "  \"nonce\": %ld,\n", block->nonce);
    fprintf(out, "  \"miner name\": \"%s\",\n", block->minerName);
    fprintf(out, "  \"comment\": \"%s\"\n", (block->index == 0) ? "genesis" : "block");
    fprintf(out, "}");
}



void print_wallets(const AppState *app) {
    printf("\nWallets:\n");
    for (int i = 0; i < app->wallet_count; i++) {
        printf("- %s : %ld BT\n", app->wallets[i].str, app->wallets[i].balance);
    }
    printf("Total supply: %ld BT\n", total_supply(app));
}

static void print_chain_json(FILE *out, const AppState *app) {
    fprintf(out, "{\n");
    fprintf(out, "\"Name\": \"bit thune\",\n");
    fprintf(out, "\"Money supply\": %ld,\n", total_supply(app));
    fprintf(out, "\"blockchain\": {\n");
    fprintf(out, "\"Difficulty\": %d,\n", app->chain.difficulty);
    fprintf(out, "\"Nb blocks\": %d,\n", app->chain.nbBlocks);
    fprintf(out, "\"Actual reward\": %d,\n", app->chain.reward4mining);
    fprintf(out, "\"blocks\": [\n");

    for (int b = 0; b < app->chain.nbBlocks; b++) {
        Block *block = get_block_at(app, b);
        if (!block) {
            continue;
        }
        print_block_json(out, block);
        fprintf(out, "%s\n", (b + 1 < app->chain.nbBlocks) ? "," : "");
    }

    fprintf(out, "]\n");
    fprintf(out, "},\n");
    fprintf(out, "\"wallets\": [\n");
    for (int i = 0; i < app->wallet_count; i++) {
        fprintf(out,
                "{\"name\": \"%s\", \"balance\": %ld}%s\n",
                app->wallets[i].str,
                app->wallets[i].balance,
                (i + 1 < app->wallet_count) ? "," : "");
    }
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

void print_chain_json_to_stdout(const AppState *app) {
    print_chain_json(stdout, app);
}

bool write_blockchain_json_file(const AppState *app, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        return false;
    }

    print_chain_json(f, app);

    fclose(f);
    return true;
}
