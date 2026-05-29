#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include "bc_config.h"

// Genere un trio (cle privee, cle publique, adresse P2PKH) pour un compte.
void crypto_generate_keypair(char *priv_hex, char *pub_hex, char *address);

// H(pubKey) = hash160 = RIPEMD160(SHA256(pubkey)) en hexa (mode reel),
void crypto_hash160(const char *pubkey_hex, char *out_hex);

// Ecrit la signature (hexa) dans 'sig_hex' (>= SIG_HEX_LEN). true si OK.
bool crypto_sign(const char *priv_hex, const char *message, char *sig_hex);

// Verifie que 'sig_hex' est une signature valide de 'message' par 'pub_hex'.
bool crypto_verify(const char *pub_hex, const char *message, const char *sig_hex);

#endif // CRYPTO_H
