#ifndef _TRIE_H_
#define _TRIE_H_ 1
#include "include/lib.h"
#include "include/protocols.h"
#include "stdlib.h"
#include "arpa/inet.h"

typedef struct trie_node_t {
    struct trie_node_t *subnodes[2];
    struct route_table_entry *entry;
} trie_node_t;

trie_node_t *create_node();
void insert_new_route(trie_node_t *root, struct route_table_entry *entry);
struct route_table_entry *get_best_route(trie_node_t *root, uint32_t ip);

#endif  // _TRIE_H_
