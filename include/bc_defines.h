#ifndef __BC_DEFINES__
#define __BC_DEFINES__

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "sha256.h"
#include "sha256_utils.h"
#include "bc_config.h" // <-- toutes les #define du projet sont ici

// structure générique de liste non typée (à typer à l'utilisation)
typedef struct Slist {
	void * info; // les elt sont des blocks ou des transactions, ce qu'on veut en fait
	struct Slist *next;
} Slist;

// structure de bloc
typedef struct block {
	int index; // numéro d'ordre
	BYTE previousHash[SHA256_BLOCK_SIZE*2 + 1];
  time_t timestamp;
	int nbTx; // nombre de transaction dans le bloc
	struct Slist * transactions; // liste de tx le nombre doit correspondre
	BYTE merkleTree[SHA256_BLOCK_SIZE*2 + 1]; // hash de l'arbre de Merkle
  BYTE blockHash[SHA256_BLOCK_SIZE*2 + 1]; // hash du bloc courant
  char minerName[MAX_STRING]; // nom du mineur
  long miningReward; // recompense effective versee au mineur pour ce bloc
  char comment[MAX_STRING];
	long nonce;
} Block;

typedef struct s_Blockchain {
  int difficulty; // nombre de zéros initiaux du hash
  int nbBlocks; // nombre de blocs de la Blockchain
	struct Slist * blocklist; // liste des blocks
  int reward4mining; // actual reward for the miner
} Blockchain;

typedef struct s_currency {
	char currency_name[MAX_STRING];
	long moneySupply; // masse monétaire en circulation
	Blockchain * bc; // la blockchain
} currency_t;

typedef struct transaction {
	BYTE txid[SHA256_BLOCK_SIZE*2 + 1]; // txid = hash(hash(tx))
  time_t timestamp; // date de création
	//time_t deadline; // date de péremption
	BYTE adSender[SHA256_BLOCK_SIZE*2 + 1]; // ou nom "user x" pour la partie 1
	BYTE adReceiver[SHA256_BLOCK_SIZE*2 + 1]; // idem
  long txAmount; // en bit_thune
  int nbInputs; // partie 2
  struct Slist * lstInputs; // une ou plusieurs UTXO (parties 2 et 3)
  int nbOutputs; // partie 2
  struct Slist * lstOutputs; // limité à trois sorties : la tx+reward+change (parties 2 et 3)
  char comment[MAX_STRING];
} Transaction;

typedef struct s_TxOutputs { //utxo (parties 2 et 3)
    int outIndex; // numéro
    // scriptPubKey P2PKH complet : DUP HASH <H(pubKey)> EQ VER (verrouille par adresse)
    char * lockingScript[SCRIPTPUBKEY_SIZE];
		time_t timestamp; // héritage de la tx
    long amount; // in milliPass
    BYTE pubKeyHash[SHA256_BLOCK_SIZE*2 + 1]; // H(pubKey) du proprietaire == identite de l'adresse
    BYTE ownerAddress[ADDRESS_STR_LEN]; // adresse P2PKH du proprietaire (ou sentinelle: FEE_POOL...)
  } TxOutputs;

typedef struct utxo{
	BYTE hash[SHA256_BLOCK_SIZE*2 + 1]; // hash de la tx contenant l'UTXO
	int indexOutput; // numéro d'ordre dans la list outputs
	TxOutputs * txOut; // pointeur vers la txOut (NULL pour une reference d'input)
	// --- Parties 3/4 : preuve de depense (scriptSig) ---
	char * scriptSig[SCRIPTSIG_SIZE];          // <sig> <pubKey>
	BYTE signature[SIG_HEX_LEN];               // partie 4 : champ signature explicite
	BYTE pubKey[PUBKEY_HEX_LEN];               // partie 4 : champ cle publique explicite
} Utxo;

typedef struct account {
  char str[MAX_STRING]; //mnémonic : plus facile à lire pour débuguer qu'une adresse
  Slist * utxoList; // liste des tx non dépensées du compte
  BYTE address[SHA256_BLOCK_SIZE*2 + 1]; // (parties 2 et 3)
	BYTE priv_key[SHA256_BLOCK_SIZE*2 + 1]; // (parties 2 et 3)
	BYTE pub_key[SHA256_BLOCK_SIZE*4 + 1]; // (parties 2 et 3)
  long balance; // solde du compte
} Account;

#endif // __BC_DEFINES__
