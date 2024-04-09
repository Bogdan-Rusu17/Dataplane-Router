#include "trie.h"

trie_node_t *create_node() {
    trie_node_t *new_node = malloc(sizeof(trie_node_t));
    new_node->entry = NULL;
    new_node->subnodes[0] = new_node->subnodes[1] = NULL;

    return new_node;
}

void insert_new_route(trie_node_t *root, struct route_table_entry *entry) {
    uint32_t mask = ntohl(entry->mask);
    uint32_t prefix = ntohl(entry->prefix);

    int bit_num = 31;
    while (bit_num >= 0 && ((1 << bit_num) & mask)) {
        int child_type = 0;
        if ((prefix & (1 << bit_num)))
            child_type = 1;
        
        if (root->subnodes[child_type] == NULL) {
            root->subnodes[child_type] = create_node();
        }

        root = root->subnodes[child_type];
        bit_num--;
    }

    root->entry = entry;

}
struct route_table_entry *get_best_route(trie_node_t *root, uint32_t ip) {
    uint32_t ip_to_search = ntohl(ip);
    struct route_table_entry *match = NULL;
    int bit_num = 31; 

    //printf("asta e ipul %u\n", ip_to_search);

    while (root && bit_num >= 0) {
        match = root->entry;
        int child_type = 0;
        if ((ip_to_search & (1 << bit_num))) {
            child_type = 1;
        }
        //printf("%d\n", child_type);

        // match = root->subnodes[child_type]->entry;
        root = root->subnodes[child_type];
        bit_num--;
    }

    return match;
}
