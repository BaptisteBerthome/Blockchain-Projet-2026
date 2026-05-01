#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "../include/blockchain_state.h"
#include "../include/blockchain_core.h"
#include "../include/utils.h"
#include "../include/bc_defines.h"
#include "../include/blockchain_io.h"

Blockchain blockchain;
Account wallets[MAX_USERS];
int nb_utilisateurs = 3;
bool est_prete = false;
static volatile sig_atomic_t stop_market_loop = 0;

static const int HALVING_LIMIT = 30;

static void on_sigint_market(int sig) {
    (void)sig;
    stop_market_loop = 1;
}

static const char *pick_random_miner_name(void) {
    if (nb_utilisateurs <= 0) {
        return "Miner";
    }
    int random_id = rand() % nb_utilisateurs;
    return wallets[random_id].str;
}

static Block *create_market_block(const Blockchain *bc) {
    Block *b = malloc(sizeof(Block));
    if (b == NULL) {
        return NULL;
    }

    memset(b, 0, sizeof(Block));
    b->index = bc->nbBlocks;
    b->timestamp = time(NULL);
    snprintf(b->minerName, MAX_STRING, "%s", pick_random_miner_name());
    return b;
}

static void advance_reward_schedule(void) {
    increment_cycle_round();
    if (get_cycle_rounds() % HALVING_LIMIT == 0) {
        long reward = get_current_reward();
        if (reward > 0) {
            set_current_reward(reward / 2);
            increment_halving_count();
            printf("[HALVING] cycle=%d nouvelle reward=%ld BT\n",
                   get_cycle_rounds(), get_current_reward());

            if (get_current_reward() == 0) {
                printf("\n========================================\n");
                printf("FIN DE LA PHASE D'INFLATION !\n");
                printf("Masse monetaire finale : %ld BT\n", get_money_supply());
                printf("Nombre de cycles de halving : %d\n", get_halving_count());
                printf("Le minage continue sur les frais uniquement.\n");
                printf("========================================\n\n");
            }
        }
    }
}

void action_initialiser() {
    printf("\n[INFO] Initialisation (Genesis + Helicopter Money)...\n");
    if (est_prete) {
        printf("\n[!] La blockchain est deja en route !\n");
        return;
    }

    blockchain.difficulty = DIFFICULTY;
    blockchain.blocklist = NULL;
    blockchain.nbBlocks = 0;
    blockchain.reward4mining = INITIALREWARD;

    reset_utxo_state();
    set_current_reward(INITIALREWARD);

    init_wallets(wallets, nb_utilisateurs);
    create_genesis_block(&blockchain);
    run_helicopter_money(&blockchain, wallets, nb_utilisateurs);

    est_prete = true;
    printf("\n[OK] Blockchain initialisee avec succes.\n");
    print_wallets(wallets, nb_utilisateurs);
}

void action_nouvelle_tx() {
    printf("\n[INFO] Creation d'une transaction UTXO...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }

    char sender[MAX_STRING];
    char receiver[MAX_STRING];
    long amount;
    char comment[MAX_STRING];

    printf("Entrez le nom de l'envoyeur (ex: user1) : ");
    scanf("%63s", sender);
    printf("Entrez le nom du receveur (ex: user2) : ");
    scanf("%63s", receiver);
    printf("Entrez le montant en Bit-Thunes : ");
    scanf("%ld", &amount);
    printf("Entrez un commentaire pour la transaction : ");
    scanf("%63s", comment);

    if (find_wallet_by_name(wallets, nb_utilisateurs, sender) == -1 ||
        find_wallet_by_name(wallets, nb_utilisateurs, receiver) == -1) {
        printf("Sender/receiver invalide. Utilisez des noms user1..user%d\n", nb_utilisateurs);
        return;
    }

    if (amount <= 0) {
        printf("Le montant doit etre strictement positif.\n");
        return;
    }

    Block *block = create_market_block(&blockchain);
    if (block == NULL) {
        printf("[ERREUR] Impossible de creer un bloc pour cette transaction.\n");
        return;
    }

    long fee = 0;
    if (!add_utxo_transaction_to_block(block, wallets, nb_utilisateurs, sender, receiver, amount, comment, &fee)) {
        printf("Transaction rejetee (solde UTXO insuffisant ou donnees invalides).\n");
        free(block);
        return;
    }

    blockchain.reward4mining = get_current_reward();
    add_coinbase_transaction(block, block->minerName, get_current_reward(), fee);
    mine_and_add_block(&blockchain, block, wallets, nb_utilisateurs);

    advance_reward_schedule();
    printf("\n[OK] Bloc mine avec transaction utilisateur.\n");
    print_wallets(wallets, nb_utilisateurs);
}

void action_mine_and_add_block() {
    printf("\n[INFO] Minage manuel d'un bloc de marche (tx aleatoires)...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }

    blockchain.reward4mining = get_current_reward();
    process_market_round(&blockchain, wallets, nb_utilisateurs, (rand() % (MAXTX - 1)) + 1);
    advance_reward_schedule();

    printf("\n[OK] Nouveau bloc de marche ajoute.\n");
    print_wallets(wallets, nb_utilisateurs);
}

void action_phase_marche() {
    printf("\n[INFO] Demarrage de la phase marche (Ctrl+C pour arreter)...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }

    stop_market_loop = 0;
    signal(SIGINT, on_sigint_market);

    while (!stop_market_loop) {
        blockchain.reward4mining = get_current_reward();
        process_market_round(&blockchain, wallets, nb_utilisateurs, (rand() % (MAXTX - 1)) + 1);
        advance_reward_schedule();
    }

    signal(SIGINT, SIG_DFL);
    printf("\n[CTRL+C] Arret de la phase marche.\n");
    printf("[STATS] Masse monetaire: %ld BT\n", get_money_supply());
    printf("[STATS] Reward courante: %ld BT\n", get_current_reward());
    printf("[STATS] Nombre de halving: %d\n", get_halving_count());
}

void action_verifier() {
    printf("\n[INFO] Verification de la chaine...\n");
    if (!est_prete) {
        printf("Initialisez la blockchain dabord.\n");
        return;
    }

    printf("vérification de la chaine...\n");

    // On appelle la fonction de core qui fait le travail mathématique
    if (verify_chain_integrity(&blockchain)) {
        printf("CHAINE VALIDE\n");
    } else {
        printf("ALERTE : CHAINE CORROMPUE\n");
    }

}

void action_sauvegarder() {
    printf("\nSauvegarde JSON...\n");
    if (!est_prete) {
        printf("Initialise la blockchain dabord.\n");
        return;
    }

    printf("\n[Sauvegarde en cours dans 'blockchain.json'...]\n");
    save_blockchain_json("blockchain.json", &blockchain, wallets, nb_utilisateurs);
    printf("Fichier enregistre avec succes !\n");
}

void action_quitter() {
    if (est_prete) {
        printf("Sauvegarde automatique avant fermeture...\n");
        action_sauvegarder();
    }
    printf("Fermeture et nettoyage de la memoire...\n");

    free_blockchain(&blockchain);
    reset_utxo_state();
}


//main
int main() {
    srand(time(NULL));
    printf("=== Bienvenue dans BIT-THUNE (Projet Blockchain 2026) ===\n");

    int choix = 0;

    //choix
    while (choix != 7) {
        printf("\n=== MENU PRINCIPAL ===\n");
        printf("1. Initialiser la blockchain\n");
        printf("2. Creer une transaction UTXO\n");
        printf("3. Miner un bloc de marche\n");
        printf("4. Verifier la chaine\n");
        printf("5. Sauvegarder en JSON\n");
        printf("6. Lancer la phase marche (infinie)\n");
        printf("7. Quitter\n");
        printf("Votre choix : ");
        
        //sécurité si l'utilisateur tape une lettre au lieu d'un chiffre
        if (scanf("%d", &choix) != 1) {
            while(getchar() != '\n');
            printf("Entree invalide, veuillez taper un chiffre.\n");
            continue;
        }


        //switch des choix
        switch (choix) {
            case 1:
                action_initialiser();
                break;
            case 2:
                action_nouvelle_tx();
                break;
            case 3:
                action_mine_and_add_block();
                break;
            case 4:
                action_verifier();
                break;
            case 5:
                action_sauvegarder();
                break;
            case 6:
                action_phase_marche();
                break;
            case 7:
                action_quitter();
                break;
            default:
                printf("Choix invalide. Veuillez taper un chiffre entre 1 et 7.\n");
                break;
        }
    }

    return 0;
}
