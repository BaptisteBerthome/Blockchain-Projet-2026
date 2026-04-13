#include "../include/blockchain_io.h"
#include "../include/blockchain_state.h"
#include <stdio.h>
#include <string.h>
#include <time.h>




// Petite fonction pour transformer le temps en texte sans le "\n" de ctime
static void get_time_str(long timestamp, char *out) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    strftime(out, 26, "%Y-%m-%d %H:%M:%S", tm_info);

}

//Affiche une transaction en format JSON
static void print_tx_json(FILE *out, const Transaction *tx) {
    char time_str[26];
    get_time_str(tx->timestamp, time_str);

    fprintf(out, "      {\n");
    fprintf(out, "        \"TxId\": \"%s\",\n", tx->txid);
    fprintf(out, "        \"Timestamp\": \"%s\",\n", time_str);
    fprintf(out, "        \"Sender\": \"%s\",\n", tx->adSender);
    fprintf(out, "        \"Receiver\": \"%s\",\n", tx->adReceiver);
    fprintf(out, "        \"Amount\": %ld,\n", tx->txAmount);
    fprintf(out, "        \"Comments\": \"%s\"\n", tx->comment);
    fprintf(out, "      }");
}
//affiche le block
void print_block_json(FILE *out, const Block *block) {
    char time_str[26];
    get_time_str(block->timestamp, time_str);

    fprintf(out, "    {\n");
    fprintf(out, "      \"index\": %d,\n", block->index);
    fprintf(out, "      \"timestamp\": \"%s\",\n", time_str);
    fprintf(out, "      \"previous_hash\": \"%s\",\n", block->previousHash);
    fprintf(out, "      \"nb_tx\": %d,\n", block->nbTx);
    fprintf(out, "      \"transactions\": [\n");

    Slist *curr = block->transactions;
    int i = 0;
    while (curr != NULL) {
        print_tx_json(out, (Transaction *)curr->info);
        if (i < block->nbTx - 1) fprintf(out, ",");
        fprintf(out, "\n");
        curr = curr->next;
        i++;
    }

    fprintf(out, "      ],\n");
    fprintf(out, "      \"merkle_root\": \"%s\",\n", block->merkleTree);
    fprintf(out, "      \"current_hash\": \"%s\",\n", block->blockHash);
    fprintf(out, "      \"nonce\": %ld,\n", block->nonce);
    fprintf(out, "      \"miner\": \"%s\",\n", block->minerName);
    fprintf(out, "      \"mining_reward\": %ld\n", block->miningReward);
    fprintf(out, "    }");
}

void print_wallets(Account wallets[MAX_USERS], int nb_users) {
    printf("\n----ETAT DES PORTEFEUILLES----\n");
    for (int i = 0; i < nb_users; i++) {
        printf("  - %-10s : %ld BT\n", wallets[i].str, wallets[i].balance);
    }
    printf("------------------------------\n");
}

void save_blockchain_json(const char *filename, Blockchain *bc, Account wallets[MAX_USERS], int nb_users) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("Impossible de créer le fichier %s\n", filename);
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"blockchain_name\": \"BIT-THUNE\",\n");
    fprintf(f, "  \"difficulty\": %d,\n", bc->difficulty);
    fprintf(f, "  \"blocks\": [\n");

    Slist *curr_block = bc->blocklist;
    int b = 0;
    while (curr_block != NULL) {
        print_block_json(f, (Block *)curr_block->info);
        if (b < bc->nbBlocks - 1) fprintf(f, ",");
        fprintf(f, "\n");
        curr_block = curr_block->next;
        b++;
    }

    fprintf(f, "  ],\n");
    fprintf(f, "  \"wallets\": [\n");
    for (int i = 0; i < nb_users; i++) {
        fprintf(f, "    {\"name\": \"%s\", \"balance\": %ld}%s\n", 
                wallets[i].str, wallets[i].balance, (i < nb_users - 1 ? "," : ""));
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("Blockchain sauvegardee dans %s\n", filename);
}
