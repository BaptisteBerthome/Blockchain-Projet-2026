#include "../include/script.h"
#include "../include/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *items[SCRIPT_STACK_MAX];
    int top; // index du prochain emplacement libre
} Stack;

static char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *c = malloc(n);
    if (c != NULL) memcpy(c, s, n);
    return c;
}

static void stack_init(Stack *st) { st->top = 0; }

static bool stack_push(Stack *st, const char *s) {
    if (st->top >= SCRIPT_STACK_MAX) return false;
    st->items[st->top] = dup_str(s);
    return st->items[st->top++] != NULL;
}

// depile dans 'out'
static bool stack_pop(Stack *st, char *out, size_t n) {
    if (st->top <= 0) return false;
    st->top--;
    snprintf(out, n, "%s", st->items[st->top]);
    free(st->items[st->top]);
    st->items[st->top] = NULL;
    return true;
}

static void stack_clear(Stack *st) {
    while (st->top > 0) {
        st->top--;
        free(st->items[st->top]);
        st->items[st->top] = NULL;
    }
}

static void stack_print(const Stack *st) {
    printf("        pile = [");
    for (int i = 0; i < st->top; i++) {
        char *it = st->items[i];
        // on tronque les longues chaines (cles/signatures) pour la lisibilite
        if (strlen(it) > 16) {
            printf("%.8s..%s", it, it + strlen(it) - 4);
        } else {
            printf("%s", it);
        }
        if (i < st->top - 1) printf(", ");
    }
    printf("]\n");
}

// scriptPubKey (dans l'output) : DUP HASH <H(pubKey)> EQ VER
void script_build_scriptpubkey(char *out[SCRIPTPUBKEY_SIZE],
                               const char *pubkeyhash_hex) {
    out[0] = dup_str(OP_DUP);
    out[1] = dup_str(OP_HASH);
    out[2] = dup_str(pubkeyhash_hex);
    out[3] = dup_str(OP_EQ);
    out[4] = dup_str(OP_VER);
}

// scriptSig (dans l'input) : <signature> <pubKey>
void script_build_scriptsig(char *out[SCRIPTSIG_SIZE],
                            const char *signature, const char *pubkey_hex) {
    out[0] = dup_str(signature);
    out[1] = dup_str(pubkey_hex);
}

static bool exec_token(Stack *st, const char *tok, const ScriptContext *ctx,
                       bool verbose, bool *script_ok) {
    char a[SIG_HEX_LEN];
    char b[SIG_HEX_LEN];

    if (strcmp(tok, OP_DUP) == 0) {
        if (st->top <= 0) return false;
        if (!stack_push(st, st->items[st->top - 1])) return false;
        if (verbose) printf("    DUP\n");

    } else if (strcmp(tok, OP_HASH) == 0) {
        if (!stack_pop(st, a, sizeof(a))) return false;
        char h[HASH160_HEX_LEN];
        crypto_hash160(a, h);
        if (!stack_push(st, h)) return false;
        if (verbose) printf("    HASH\n");

    } else if (strcmp(tok, OP_EQ) == 0) {
        // compare et CONSOMME les deux sommets (comme EQUALVERIFY)
        if (!stack_pop(st, a, sizeof(a))) return false;
        if (!stack_pop(st, b, sizeof(b))) return false;
        if (strcmp(a, b) != 0) {
            *script_ok = false;
            if (verbose) printf("    EQ -> FAUX (hash differents)\n");
            return false;
        }
        if (verbose) printf("    EQ -> ok\n");

    } else if (strcmp(tok, OP_VER) == 0) {
        // <sign> <pubKey> VER : pubKey au sommet, signature juste dessous
        if (!stack_pop(st, a, sizeof(a))) return false; // pubKey
        if (!stack_pop(st, b, sizeof(b))) return false; // signature
        const char *msg = (ctx != NULL && ctx->message != NULL) ? ctx->message : "";
        bool valid = crypto_verify(a, msg, b);
        *script_ok = *script_ok && valid;
        if (verbose) printf("    VER -> %s\n", valid ? "signature VALIDE" : "signature INVALIDE");
        if (!valid) return false;

    } else {
        // donnee : on empile
        if (!stack_push(st, tok)) return false;
        if (verbose) printf("    PUSH %.16s%s\n", tok, strlen(tok) > 16 ? ".." : "");
    }

    if (verbose) stack_print(st);
    return true;
}

bool script_execute(char *const scriptSig[SCRIPTSIG_SIZE],
                    char *const scriptPubKey[SCRIPTPUBKEY_SIZE],
                    const ScriptContext *ctx,
                    bool verbose) {
    Stack st;
    stack_init(&st);
    bool script_ok = true;

    if (verbose) printf("    --- execution du script (scriptSig ++ scriptPubKey) ---\n");

    for (int i = 0; i < SCRIPTSIG_SIZE; i++) {
        if (scriptSig[i] == NULL) continue;
        if (!exec_token(&st, scriptSig[i], ctx, verbose, &script_ok)) {
            stack_clear(&st);
            return false;
        }
    }
    for (int i = 0; i < SCRIPTPUBKEY_SIZE; i++) {
        if (scriptPubKey[i] == NULL) continue;
        if (!exec_token(&st, scriptPubKey[i], ctx, verbose, &script_ok)) {
            stack_clear(&st);
            return false;
        }
    }

    stack_clear(&st);
    return script_ok;
}
