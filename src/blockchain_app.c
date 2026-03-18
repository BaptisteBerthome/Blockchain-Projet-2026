#include "blockchain_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blockchain_core.h"
#include "blockchain_io.h"
#include "blockchain_state.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

enum MenuChoice {
    MENU_QUIT = 0,
    MENU_CREATE_CHAIN = 1,
    MENU_HELICOPTER = 2,
    MENU_SHOW_WALLETS = 3,
    MENU_VERIFY = 4,
    MENU_CREATE_TX = 5,
    MENU_MINE_PENDING = 6,
    MENU_PRINT_CHAIN_JSON = 7,
    MENU_SAVE_JSON = 8,
};

static void clear_stdin(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
}

static void wait_for_enter(void) {
    printf("\nPress Enter to return to menu...");
    fflush(stdout);
    (void)getchar();
}


void clearScreen(){
    int rc = system("cls");
    if (rc != 0) {
        rc = system("clear");
    }

    if (rc != 0) {
        const char *clear_screen_ansi = "\x1b[2J\x1b[H";
        write(STDOUT_FILENO, clear_screen_ansi, 7);
        fflush(stdout);
    }
}


static int ask_int(const char *prompt, int min_v, int max_v) {
    int value;
    while (1) {
        printf("%s", prompt);
        if (scanf("%d", &value) == 1 && value >= min_v && value <= max_v) {
            clear_stdin();
            return value;
        }
        clear_stdin();
        printf("Invalid input. Expected integer in [%d..%d].\n", min_v, max_v);
    }
}

static long ask_long(const char *prompt, long min_v) {
    long value;
    while (1) {
        printf("%s", prompt);
        if (scanf("%ld", &value) == 1 && value >= min_v) {
            clear_stdin();
            return value;
        }
        clear_stdin();
        printf("Invalid input. Expected integer >= %ld.\n", min_v);
    }
}

static void ask_text(const char *prompt, char *out, size_t out_size) {
    printf("%s", prompt);
    if (fgets(out, (int)out_size, stdin) == NULL) {
        out[0] = '\0';
        return;
    }
    size_t len = strlen(out);
    if (len > 0 && out[len - 1] == '\n') {
        out[len - 1] = '\0';
    }
}

static void create_blockchain_interactive(AppState *app) {
    char prompt[80];
    snprintf(prompt, sizeof(prompt), "Number of users (1..%d): ", MAX_USERS);
    int users = ask_int(prompt, 1, MAX_USERS);
    create_blockchain_with_users(app, users);
    printf("Blockchain created with genesis block and %d users.\n", users);
    print_wallets(app);
}

static void create_user_transaction_interactive(AppState *app) {
    if (!app->initialized) {
        printf("Create blockchain first.\n");
        return;
    }

    char sender[MAX_STRING];
    char receiver[MAX_STRING];
    ask_text("Emitter (e.g. user1): ", sender, sizeof(sender));
    ask_text("Receiver (e.g. user2): ", receiver, sizeof(receiver));
    long amount = ask_long("Amount (BT, >=1): ", 1);
    (void)create_user_transaction_by_name(app, sender, receiver, amount);
}

static void save_chain_json_interactive(AppState *app) {
    if (!app->initialized) {
        printf("Create blockchain first.\n");
        return;
    }

    char filename[256];
    char outpath[512];
    ask_text("JSON filename (example: chain.json): ", filename, sizeof(filename));
    if (filename[0] == '\0') {
        printf("Cancelled.\n");
        return;
    }

    snprintf(outpath, sizeof(outpath), "build/json/%s", filename);

    if (write_blockchain_json_file(app, outpath)) {
        printf("Blockchain saved to %s\n", outpath);
    } else {
        printf("Cannot write file %s\n", outpath);
    }
}

void app_init(AppState *app) {
    memset(app, 0, sizeof(*app));
    srand((unsigned int)time(NULL));
}

void app_shutdown(AppState *app) {
    free_blockchain_memory(app);
}

void app_print_menu(const AppState *app) {
    clearScreen();
    printf(ANSI_COLOR_CYAN "\n--------------------------------------------------------------\n" ANSI_COLOR_RESET);

    if (app->initialized) {
        int pending_tx_count = 0;
        if (app->pending_block != NULL) {
            for (Slist *node = app->pending_block->transactions; node != NULL; node = node->next) {
                Transaction *tx = (Transaction *)node->info;
                if (strcmp((char *)tx->adSender, COINBASE_NAME) != 0) {
                    pending_tx_count++;
                }
            }
        }
        printf(ANSI_COLOR_GREEN "Status : READY\n" ANSI_COLOR_RESET);
        printf("Users  : %d\n", app->wallet_count);
        printf("Blocks : %d\n", app->chain.nbBlocks);
        printf("Reward : %d BTC\n", app->chain.reward4mining);
        printf("Supply : %ld BTC\n", total_supply(app));
        printf(ANSI_COLOR_YELLOW "Pending: %d / %d tx\n" ANSI_COLOR_RESET,
               pending_tx_count,
               MAXTX - 1);
    } else {
        printf(ANSI_COLOR_RED "Status : NOT INITIALIZED\n" ANSI_COLOR_RESET);
        printf(ANSI_COLOR_YELLOW "Hint   : Create blockchain first.\n" ANSI_COLOR_RESET);
    }

    printf(ANSI_COLOR_BLUE "--------------------------------------------------------------\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "[ BLOCKCHAIN ]\n" ANSI_COLOR_RESET);
    printf("  1) Create blockchain (genesis + users)\n");
    printf("  2) Run helicopter money\n");
    printf("  3) Show wallets\n");
    printf("  4) Verify blockchain integrity\n");
    printf(ANSI_COLOR_MAGENTA "--------------------------------------------------------------\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_MAGENTA "[ TRANSACTIONS ]\n" ANSI_COLOR_RESET);
    printf("  5) Add transaction (pending block)\n");
    printf("  6) Mine pending block\n");
    printf(ANSI_COLOR_GREEN "--------------------------------------------------------------\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN "[ OUTPUT ]\n" ANSI_COLOR_RESET);
    printf("  7) Print blockchain as JSON\n");
    printf("  8) Save blockchain to JSON\n");
    printf(ANSI_COLOR_RED "--------------------------------------------------------------\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_RED "  0) Quit\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_CYAN "==============================================================\n" ANSI_COLOR_RESET);
}

int app_read_choice(void) {
    return ask_int(ANSI_COLOR_YELLOW "Choose: " ANSI_COLOR_RESET, 0, 8);
}

bool app_handle_choice(AppState *app, int choice) {
    switch (choice) {
        case MENU_QUIT:
            if (app->initialized && app->pending_block != NULL) {
                printf("Pending block detected. Mining before exit...\n");
                (void)mine_pending_block(app);
            }
            return false;
        case MENU_CREATE_CHAIN:
            create_blockchain_interactive(app);
            break;
        case MENU_CREATE_TX:
            create_user_transaction_interactive(app);
            break;
        case MENU_VERIFY:
            if (!app->initialized) {
                printf("Create blockchain first.\n");
            } else if (verify_chain_integrity(app)) {
                printf("Blockchain integrity OK.\n");
            }
            break;
        case MENU_SAVE_JSON:
            save_chain_json_interactive(app);
            break;
        case MENU_HELICOPTER:
            (void)run_helicopter_money_internal(app);
            break;
        case MENU_SHOW_WALLETS:
            if (!app->initialized) {
                printf("Create blockchain first.\n");
            } else {
                print_wallets(app);
            }
            break;
        case MENU_PRINT_CHAIN_JSON:
            if (!app->initialized) {
                printf("Create blockchain first.\n");
            } else {
                print_chain_json_to_stdout(app);
            }
            break;
        case MENU_MINE_PENDING:
            if (!app->initialized) {
                printf("Create blockchain first.\n");
            } else if (app->pending_block == NULL) {
                printf("No pending block to mine.\n");
            } else {
                (void)mine_pending_block(app);
            }
            break;
        default:
            break;
    }

    if (app->initialized) {
        printf("Current monetary supply: %ld BT\n", total_supply(app));
    }

    wait_for_enter();

    return true;
}
