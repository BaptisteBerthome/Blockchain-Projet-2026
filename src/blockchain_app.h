#ifndef BLOCKCHAIN_APP_H
#define BLOCKCHAIN_APP_H

#include <stdbool.h>
#include "../lib/bc_defines.h"

#define COINBASE_NAME "coinbase"
#define HELICOPTER_AMOUNT 50000L

typedef struct {
    Blockchain chain;
    Account wallets[MAX_USERS];
    int wallet_count;
    bool initialized;
    Block *pending_block;
} AppState;

void app_init(AppState *app);
void app_shutdown(AppState *app);
void app_print_menu(const AppState *app);
int app_read_choice(void);
bool app_handle_choice(AppState *app, int choice);

#endif
