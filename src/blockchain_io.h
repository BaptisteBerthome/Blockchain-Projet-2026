#ifndef BLOCKCHAIN_IO_H
#define BLOCKCHAIN_IO_H

#include <stdbool.h>
#include <stdio.h>
#include "blockchain_app.h"

void print_block_json(FILE *out, const Block *block);
void print_wallets(const AppState *app);
void print_chain_json_to_stdout(const AppState *app);
bool write_blockchain_json_file(const AppState *app, const char *filename);

#endif
