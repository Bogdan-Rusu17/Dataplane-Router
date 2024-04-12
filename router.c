#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include "trie.h"
#include "utils.h"

#define MAX_TABLE_ENTRIES 100000

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

trie_node_t *root;

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(MAX_TABLE_ENTRIES * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);
	root = create_node();
	for (int i = 0; i < rtable_len; i++)
		insert_new_route(root, &rtable[i]);

	queue waiting_arp_queue = queue_create();
	arp_table = malloc(MAX_TABLE_ENTRIES * sizeof(struct arp_table_entry));

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {  // IP header
			struct iphdr *iph = (struct iphdr *)(buf + 
			 									 sizeof(struct ether_header));

			// packet to destIP = router_interf_ip means ICMP Echo Request
			if (iph->daddr == inet_addr(get_interface_ip(interface))) {
				struct icmphdr *icmph = (struct icmphdr *)(buf + 
														   sizeof(struct ether_header) +
														   sizeof(struct iphdr));
				if (icmph->type == 8 && icmph->code == 0) {  // ICMP Echo request
					send_icmp_echo_reply(interface, buf, len);
				}

				continue;
			}

			// verify if checksum is good, else drop
			uint16_t old_checksum = ntohs(iph->check);
			iph->check = 0;
			if (old_checksum != checksum((uint16_t *)iph, sizeof(struct iphdr))) {
				continue;
			}

			// we put it back to the actual value, not 0
			iph->check = htons(old_checksum);

			// verify if ttl is good, if not send icmp tle echo reply
			if (iph->ttl <= 1) {
				send_icmp_tle_reply(interface, buf, len);
				continue;
			}
			
			// update checksum efficiently
			uint16_t old_ttl = iph->ttl;
			iph->ttl--;
			iph->check = ~(~iph->check + ~((uint16_t)old_ttl) + (uint16_t)iph->ttl) - 1;

			// search trie aka routing table to find best route
			struct route_table_entry *best_route = get_best_route(root, iph->daddr);
			// if route doesn't exist, send destination unreachable icmp echo reply
			if (best_route == NULL) {
				send_icmp_dest_unreachable_reply(interface, buf, len);
				continue;
			}

			// we look in the dinamically build arp table if there exists and entry for next hop
			struct arp_table_entry *next_hop_entry = get_arp_entry_by_ip(arp_table, arp_table_len, best_route);

			if (next_hop_entry == NULL) {
				package *pack_to_enq = malloc(sizeof(package));
				pack_to_enq->buf = calloc(1, MAX_PACKET_LEN);
				memcpy(pack_to_enq->buf, buf, len);
				pack_to_enq->len = len;
				pack_to_enq->best_route = best_route;

				queue_enq(waiting_arp_queue, pack_to_enq);
				send_arp_request(best_route, interface, buf, len);

				continue;
			}

			memcpy(eth_hdr->ether_dhost, next_hop_entry->mac, MAC_LEN);
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			send_to_link(best_route->interface, buf, len);
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arphdr = (struct arp_header *)(buf +
															  sizeof(struct ether_header));
			// check if we got an arp request
			// if destination ip matches and destination mac is 0xffffffffffff
			// send reply with our mac address
			if (ntohs(arphdr->op) == ARPOP_REQUEST) {
				if (arphdr->tpa == inet_addr(get_interface_ip(interface))) {
					send_arp_reply(buf, interface, len);
				}
				continue;
			}

			if (ntohs(arphdr->op) == ARPOP_REPLY) {
				
				// we check if the request for the specific ip was already
				// put in the arp table
				char existsEntry = 0;
				for (int i = 0; i < arp_table_len; i++)
					if (arphdr->spa == arp_table[i].ip)
						existsEntry = 1;
				if (existsEntry == 1)
					continue;
				
				memcpy(&arp_table[arp_table_len].ip, &arphdr->spa, sizeof(uint32_t));
				memcpy(arp_table[arp_table_len].mac, arphdr->sha, MAC_LEN);

				arp_table_len++;
				queue tmp_q = queue_create();
				while (!queue_empty(waiting_arp_queue)) {
					package *pack = queue_deq(waiting_arp_queue);

					struct ether_header *pack_eth_hdr = (struct ether_header *)pack->buf;

					if (pack->best_route && pack->best_route->next_hop == arp_table[arp_table_len - 1].ip) {
						memcpy(pack_eth_hdr->ether_dhost, arp_table[arp_table_len - 1].mac, MAC_LEN);
						get_interface_mac(pack->best_route->interface, pack_eth_hdr->ether_shost);

						send_to_link(pack->best_route->interface, pack->buf, pack->len);
					} else {
						queue_enq(tmp_q, pack);
					}
				}
				waiting_arp_queue = tmp_q;
			}
		}
	}
}

