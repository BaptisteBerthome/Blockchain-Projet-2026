#ifndef SCRIPT_H
#define SCRIPT_H

#include <stdbool.h>
#include "bc_config.h"

// Contexte d'execution : le message (txid) que VER doit verifier.
typedef struct {
    const char *message;
} ScriptContext;

// scriptPubKey (output) : DUP HASH <pubKeyHash> EQ VER. Chaines dupliquees.
void script_build_scriptpubkey(char *out[SCRIPTPUBKEY_SIZE],
                               const char *pubkeyhash_hex);

// scriptSig (input) : <signature> <pubKey>. Chaines dupliquees.
void script_build_scriptsig(char *out[SCRIPTSIG_SIZE],
                            const char *signature, const char *pubkey_hex);

// Concatene scriptSig ++ scriptPubKey et execute sur la pile.
bool script_execute(char *const scriptSig[SCRIPTSIG_SIZE],
                    char *const scriptPubKey[SCRIPTPUBKEY_SIZE],
                    const ScriptContext *ctx,
                    bool verbose);

#endif // SCRIPT_H
