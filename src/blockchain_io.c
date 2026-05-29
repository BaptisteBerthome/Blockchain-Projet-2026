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
    fprintf(out, "        \"NbInputs\": %d,\n", tx->nbInputs);

    fprintf(out, "        \"Inputs\": [\n");
    Slist *in_node = tx->lstInputs;
    while (in_node != NULL) {
        Utxo *in = (Utxo *)in_node->info;
        fprintf(out, "          {\"prevTxId\": \"%.16s..\", \"index\": %d,\n", in->hash, in->indexOutput);
        fprintf(out, "           \"signature\": \"%s\",\n", in->signature);
        fprintf(out, "           \"pubKey\": \"%s\",\n", in->pubKey);
        fprintf(out, "           \"scriptSig\": \"%s %s\"}",
                in->scriptSig[0] ? in->scriptSig[0] : "",
                in->scriptSig[1] ? in->scriptSig[1] : "");
        if (in_node->next != NULL) {
            fprintf(out, ",");
        }
        fprintf(out, "\n");
        in_node = in_node->next;
    }
    fprintf(out, "        ],\n");

    fprintf(out, "        \"NbOutputs\": %d,\n", tx->nbOutputs);
    fprintf(out, "        \"Outputs\": [\n");

    Slist *out_node = tx->lstOutputs;
    int idx = 0;
    while (out_node != NULL) {
        TxOutputs *tx_out = (TxOutputs *)out_node->info;
        const char *owner = "UNKNOWN";
        const char *pkh = "";
        char scriptpubkey[256] = "";
        long amount = 0;
        int out_index = idx;

        if (tx_out != NULL) {
            owner = (const char *)tx_out->ownerAddress;
            pkh = (const char *)tx_out->pubKeyHash;
            amount = tx_out->amount;
            out_index = tx_out->outIndex;
            scriptpubkey[0] = '\0';
            for (int k = 0; k < SCRIPTPUBKEY_SIZE; k++) {
                if (tx_out->lockingScript[k] != NULL) {
                    strncat(scriptpubkey, tx_out->lockingScript[k],
                            sizeof(scriptpubkey) - strlen(scriptpubkey) - 2);
                    strncat(scriptpubkey, " ", sizeof(scriptpubkey) - strlen(scriptpubkey) - 1);
                }
            }
        }

        fprintf(out, "          {\"index\": %d, \"ownerAddress\": \"%s\", \"pubKeyHash\": \"%s\", \"scriptPubKey\": \"%s\", \"amount\": %ld}",
                out_index, owner, pkh, scriptpubkey, amount);
        if (out_node->next != NULL) {
            fprintf(out, ",");
        }
        fprintf(out, "\n");

        out_node = out_node->next;
        idx++;
    }

    fprintf(out, "        ],\n");
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
        printf("  - %-8s (%s) : %ld BT\n", wallets[i].str, wallets[i].address, wallets[i].balance);
    }
    printf("------------------------------\n");
}

void print_address_book(Account wallets[MAX_USERS], int nb_users) {
    printf("\n--- CARNET D'ADRESSES ---\n");
    for (int i = 0; i < nb_users; i++) {
        printf("  %-6s -> %s (%ld BT)\n", wallets[i].str, wallets[i].address, wallets[i].balance);
    }
    printf("-------------------------\n");
}

void print_wallet_keys(Account wallets[MAX_USERS], int nb_users) {
    printf("\n======= CLES ET ADRESSES (P2PKH) =======\n");
    for (int i = 0; i < nb_users; i++) {
        printf("[%s]\n", wallets[i].str);
        printf("  Cle privee : %s\n", wallets[i].priv_key);
        printf("  Cle publique : %s\n", wallets[i].pub_key);
        printf("  Adresse    : %s\n", wallets[i].address);
        printf("  Solde      : %ld BT\n", wallets[i].balance);
    }
    printf("========================================\n");
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
        fprintf(f, "    {\"name\": \"%s\", \"address\": \"%s\", \"pubKey\": \"%s\", \"balance\": %ld}%s\n",
                wallets[i].str, wallets[i].address, wallets[i].pub_key,
                wallets[i].balance, (i < nb_users - 1 ? "," : ""));
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("Blockchain sauvegardee dans %s\n", filename);
}
