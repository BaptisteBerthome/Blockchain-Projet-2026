#ifndef BLOCKCHAIN_IO_H
#define BLOCKCHAIN_IO_H

#include <stdio.h>
#include "bc_defines.h"

//Affiche un bloc seul (format JSON)
void print_block_json(FILE *out, const Block *block);

//Affiche le solde de tous les utilisateurs
void print_wallets(Account wallets[MAX_USERS], int nb_users);

//Sauvegarde toute la blockchain dans un fichier .json
void save_blockchain_json(const char *filename, Blockchain *bc, Account wallets[MAX_USERS], int nb_users);

#endif
