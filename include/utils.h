#ifndef UTILS_H
#define UTILS_H

#include "bc_defines.h"

//Ajoute un élement à la fin de la liste et retourne le nouveau début de liste
Slist* Slist_add(Slist *list, void *new_info);

//Compte le nombre d'éléments dans la liste
int Slist_count(Slist *list);

//Libere les maillons de la liste (pas le contenu)
void Slist_free_nodes(Slist *list);

//Libere un bloc et toute les transaction qu'il contient
void free_block(Block *b);

//Libere toute la blockchain (tous les blocs et la structure elle-meme)
void free_blockchain(Blockchain *bc);

#endif