#include "blockchain_app.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    AppState *app = (AppState *)malloc(sizeof(AppState));
    if (app == NULL) {
        fprintf(stderr, "Cannot allocate app state.\n");
        return 1;
    }
    app_init(app);

    while (1) {
        app_print_menu(app);
        int choice = app_read_choice();
        if (!app_handle_choice(app, choice)) {
            break;
        }
    }

    app_shutdown(app);
    free(app);

    return 0;
}
