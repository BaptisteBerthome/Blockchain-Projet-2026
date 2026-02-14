#ifndef __BC_DEFINES__
#define __BC_DEFINES__
// Header donné à titre indicatif (en clair vous pouvez l'ignorer et faire le vôtre)
//
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "sha256.h"
#include "sha256_utils.h"

#define MAX_BUF 1024
#define MAX_STRING 64
#define MAX_BLOCK 15
#define MAXTX 10 // nb tx par bloc (tests)
#define DIFFICULTY 4 // difficulté pour le minage
#define INITIALREWARD 50*1000 // montant de départ de la récompence des mineurs
#define HELIREWARD 100*1000 // montant de l'helicopter money
#define MAX_USERS 3 // nb utilisateurs (tests)
#define LOCK_SCRIPT_SIZE 4 // (parties 2 et 3)
#define UNLOCK_SCRIPT_SIZE 3 // (parties 2 et 3)
#define FEE_RATE 5 //%
#define HALVING 10 // nombre de blocs pour diviser la récompence
#define HASHLENGTH SHA256_BLOCK_SIZE*2 + 1

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

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
    char * lockingScript[LOCK_SCRIPT_SIZE];
		time_t timestamp; // héritage de la tx
    long amount; // in milliPass
  } TxOutputs;

typedef struct utxo{
	BYTE hash[SHA256_BLOCK_SIZE*2 + 1]; // hash de la tx contenant l'UTXO
	int indexOutput; // numéro d'ordre dans la list outputs
	TxOutputs * txOut; // pointeur vers la txOut
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
