#include <stdio.h>
#include <stdlib.h>

#include "../src/blockchain_app.h"
#include "blockchain_test.h"

int main(void) {
    AppState *app = (AppState *)malloc(sizeof(AppState));
    if (app == NULL) {
        fprintf(stderr, "Failed to allocate AppState\n");
        return 1;
    }

    app_init(app);
    run_autotest(app);
    app_shutdown(app);
    free(app);
    return 0;
}