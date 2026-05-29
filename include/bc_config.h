#ifndef __BC_CONFIG__
#define __BC_CONFIG__
// ------------------------- TAILLES / BUFFERS -------------------------
#define MAX_BUF      1024  // taille generique de tampon
#define MAX_STRING   64    // taille des petites chaines (noms, commentaires)
#define MAX_BLOCK    15    // nb max de blocs (tests)
#define MAXTX        10    // nb max de tx par bloc (tests)

// longueur d'un hash en hexadecimal (+1 pour le '\0') == SHA256_BLOCK_SIZE*2+1
#define HASHLENGTH   65

// ------------------------- BLOCKCHAIN / MINAGE -----------------------
#define DIFFICULTY     4         // nombre de zeros initiaux du hash (minage)
#define INITIALREWARD  (25*1000) // recompense de depart du mineur (25k)
#define HELIREWARD     (50*1000) // helicopter money : 50k par utilisateur
#define MAX_USERS      3         // nombre d'utilisateurs (tests)

// ------------------------- ECONOMIE ----------------------------------
#define FEE_RATE        5        // commission en % du montant de la tx
#define HALVING         10       // (indicatif) nb de blocs avant halving
#define HALVING_LIMIT   30       // halving : on divise la reward tous les N cycles
#define MARKET_MAX_TX_AMOUNT 3000 // montant max d'une tx aleatoire (phase marche)

// ------------------------- SCRIPTS (PARTIE 3) ------------------------
// Modele P2PKH complet (comme Bitcoin) :
//   scriptSig    (input)  : <sig> <pubKey>
//   scriptPubKey (output) : DUP HASH <H(pubKey)> EQ VER
//   execution = scriptSig ++ scriptPubKey, de gauche a droite sur la pile.
#define SCRIPTSIG_SIZE      2    // <sig> <pubKey>
#define SCRIPTPUBKEY_SIZE   5    // DUP HASH <H(pubKey)> EQ VER
#define SCRIPT_STACK_MAX    32   // profondeur max de la pile d'execution

// (tailles "historiques" de l'enonce, conservees pour reference)
#define LOCK_SCRIPT_SIZE    4    // <Tx sign A> <pubKey A> DUP HASH
#define UNLOCK_SCRIPT_SIZE  3    // <H(pubKey A)> EQ VER

// Opcodes du mini-langage de script (4 instructions)
#define OP_DUP   "DUP"   // duplique le sommet de pile
#define OP_HASH  "HASH"  // hash le sommet de pile
#define OP_EQ    "EQ"    // compare (et consomme) les 2 sommets ; echec si differents
#define OP_VER   "VER"   // verifie la signature : <sign> <pubKey> -> true si valide



#ifndef USE_REAL_ECDSA
#define USE_REAL_ECDSA   1
#endif

#define ADDRESS_VERSION_BYTE  0x00 // 0x00 -> adresses mainnet qui commencent par '1'

// Tailles des tampons cryptographiques (hexa + '\0')
#define PRIVKEY_HEX_LEN   67   // cle privee : 64 hex
#define PUBKEY_HEX_LEN    132  // cle publique compressee : 66 hex (marge)
#define HASH160_HEX_LEN   41   // RIPEMD160(SHA256(x)) : 40 hex
#define ADDRESS_STR_LEN   40   // adresse base58 (~34 car)
#define SIG_HEX_LEN       256  // signature DER en hexa (variable, ~140-144)

// --------------------------------------------------------------------
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#endif // __BC_CONFIG__
