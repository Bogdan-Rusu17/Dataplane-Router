#include "utils.h"

void send_icmp_echo_reply(int interface, char *pack, size_t pack_len) {
    struct ether_header *ethhdr = (struct ether_header *) pack;
    struct iphdr *iph = (struct iphdr *)(pack + 
			 							 sizeof(struct ether_header));
    struct icmphdr *icmph = (struct icmphdr *)(pack + 
                                               sizeof(struct ether_header) +
                                               sizeof(struct iphdr));
    // mark as echo reply, type = 0, code = 0
    icmph->type = 0;
    icmph->checksum = 0;
    icmph->code = 0;
    icmph->un.echo.id = 0;
    icmph->un.echo.sequence = 0;
    icmph->checksum = htons(checksum((uint16_t *)icmph, sizeof(struct icmphdr)));

    // swap mac addresses
    uint8_t tmp[6];
    memcpy(tmp, ethhdr->ether_dhost, MAC_LEN);
    memcpy(ethhdr->ether_dhost, ethhdr->ether_shost, MAC_LEN);
    memcpy(ethhdr->ether_shost, tmp, MAC_LEN);
    
    // swap ip addresses
    uint32_t tmpIP = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = tmpIP;
    
    // send it to where it came from
    send_to_link(interface, pack, pack_len);
}

void send_icmp_tle_reply(int interface, char *pack, size_t pack_len) {
    struct ether_header *ethhdr = (struct ether_header *) pack;
    struct iphdr *iph = (struct iphdr *)(pack + 
			 							 sizeof(struct ether_header));
    
    struct ether_header *to_send_ethhdr = malloc(sizeof(struct ether_header));
    struct iphdr *to_send_iphdr = malloc(sizeof(struct iphdr));
    struct icmphdr *to_send_icmphdr = malloc(sizeof(struct icmphdr));

    // building icmp header
    // mark as tle reply, type = 11, code = 0
    to_send_icmphdr->type = 11;
    to_send_icmphdr->code = 0;
    to_send_icmphdr->un.echo.id = 0;
    to_send_icmphdr->un.echo.sequence = 0;
    to_send_icmphdr->checksum = 0;
    to_send_icmphdr->checksum = htons(checksum((uint16_t *)to_send_icmphdr, sizeof(struct icmphdr)));

    // building ip header
    to_send_iphdr->daddr = iph->saddr;
    to_send_iphdr->saddr = iph->daddr;
    to_send_iphdr->protocol = IPPROTO_ICMP;
    to_send_iphdr->ihl = 5;
    to_send_iphdr->version = 4;
    to_send_iphdr->ttl = 64;
    to_send_iphdr->tos = 0;
    to_send_iphdr->frag_off = 0;
    to_send_iphdr->id = htons(1);
    to_send_iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    to_send_iphdr->check = 0;
    to_send_iphdr->check = htons(checksum((uint16_t *)to_send_iphdr, sizeof(struct iphdr)));

    // building ether header
    memcpy(to_send_ethhdr->ether_dhost, ethhdr->ether_shost, MAC_LEN);
    memcpy(to_send_ethhdr->ether_shost, ethhdr->ether_dhost, MAC_LEN);
    to_send_ethhdr->ether_type = htons(ETHERTYPE_IP);

    // building packet
    char *to_send_buf = calloc(1, MAX_PACKET_LEN);
    memcpy(to_send_buf, to_send_ethhdr, sizeof(struct ether_header));
    memcpy(to_send_buf + sizeof(struct ether_header), to_send_iphdr, sizeof(struct iphdr));
    memcpy(to_send_buf + sizeof(struct ether_header) + sizeof(struct iphdr),
           to_send_icmphdr, sizeof(struct icmphdr));
    memcpy(to_send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
           iph, sizeof(struct iphdr));
    // also putting first 8 bytes of the received payload after the ip header
    memcpy(to_send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr),
           pack + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

    size_t buf_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

    // send it to where it came from
    send_to_link(interface, to_send_buf, buf_len);
}

void send_icmp_dest_unreachable_reply(int interface, char *pack, size_t pack_len) {
    struct ether_header *ethhdr = (struct ether_header *) pack;
    struct iphdr *iph = (struct iphdr *)(pack + 
			 							 sizeof(struct ether_header));
    
    struct ether_header *to_send_ethhdr = malloc(sizeof(struct ether_header));
    struct iphdr *to_send_iphdr = malloc(sizeof(struct iphdr));
    struct icmphdr *to_send_icmphdr = malloc(sizeof(struct icmphdr));

    // building icmp header
    // mark as dest unreachable reply, type = 3, code = 0
    to_send_icmphdr->type = 3;
    to_send_icmphdr->code = 0;
    to_send_icmphdr->un.echo.id = 0;
    to_send_icmphdr->un.echo.sequence = 0;
    to_send_icmphdr->checksum = 0;
    to_send_icmphdr->checksum = htons(checksum((uint16_t *)to_send_icmphdr, sizeof(struct icmphdr)));

    // building ip header
    to_send_iphdr->daddr = iph->saddr;
    to_send_iphdr->saddr = iph->daddr;
    to_send_iphdr->protocol = IPPROTO_ICMP;
    to_send_iphdr->ihl = 5;
    to_send_iphdr->version = 4;
    to_send_iphdr->ttl = 64;
    to_send_iphdr->tos = 0;
    to_send_iphdr->frag_off = 0;
    to_send_iphdr->id = htons(1);
    to_send_iphdr->check = 0;
    to_send_iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    to_send_iphdr->check = htons(checksum((uint16_t *)to_send_iphdr, sizeof(struct iphdr)));

    // building ether header
    memcpy(to_send_ethhdr->ether_dhost, ethhdr->ether_shost, MAC_LEN);
    memcpy(to_send_ethhdr->ether_shost, ethhdr->ether_dhost, MAC_LEN);
    to_send_ethhdr->ether_type = htons(ETHERTYPE_IP);

    // building packet
    char *to_send_buf = calloc(1, MAX_PACKET_LEN);
    memcpy(to_send_buf, to_send_ethhdr, sizeof(struct ether_header));
    memcpy(to_send_buf + sizeof(struct ether_header), to_send_iphdr, sizeof(struct iphdr));
    memcpy(to_send_buf + sizeof(struct ether_header) + sizeof(struct iphdr),
           to_send_icmphdr, sizeof(struct icmphdr));
    memcpy(to_send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
           iph, sizeof(struct iphdr));
    // also putting first 8 bytes of the received payload after the ip header
    memcpy(to_send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr),
           pack + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

    size_t buf_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

    // send it to where it came from
    send_to_link(interface, to_send_buf, buf_len);
}

struct arp_table_entry *get_arp_entry_by_ip(struct arp_table_entry *arp_table,
                                           int arp_table_len,
                                           struct route_table_entry *best_route) {
    for (int i = 0; i < arp_table_len; i++)
        if (best_route->next_hop == arp_table[i].ip)
            return &arp_table[i];
    return NULL;
}

void send_arp_request(struct route_table_entry *best_route,
                      int interface,
                      char *pack,
                      size_t pack_len) {
    // constructing ethernet header
    struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
    uint8_t dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth_hdr->ether_dhost, dest_mac, MAC_LEN);
    get_interface_mac(best_route->interface, eth_hdr->ether_shost);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    // constructing arp header
    struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
    arp_hdr->htype = htons(ARPHRD_ETHER);
    arp_hdr->hlen = MAC_LEN;
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->plen = IP_LEN;
    arp_hdr->op = htons(ARPOP_REQUEST);

    get_interface_mac(best_route->interface, arp_hdr->sha);
    memcpy(arp_hdr->tha, eth_hdr->ether_dhost, MAC_LEN);
    arp_hdr->tpa = best_route->next_hop;
    arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));

    // construct new package to send
    char *buf_to_send = calloc(1, PACKAGE_MAX_LEN);
    memcpy(buf_to_send, eth_hdr, sizeof(struct ether_header));
    memcpy(buf_to_send + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
    size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

    send_to_link(best_route->interface, buf_to_send, len);

}

void send_arp_reply(char *buf, int interface, size_t len) {
    uint32_t old_sender, old_receiver;
    struct ether_header *ethhdr = (struct ether_header *)buf;
    struct arp_header *arphdr = (struct arp_header *)(buf + sizeof(struct ether_header));

    old_sender = arphdr->spa;
    old_receiver = arphdr->tpa;

    // we swap those two to send back the reply
    arphdr->tpa = old_sender;
    arphdr->spa = old_receiver;

    // now we swap mac addresses
    uint8_t tmp_mac[6];
    get_interface_mac(interface, tmp_mac);

    // tmp_mac holds the old receiver hardware address
    memcpy(arphdr->tha, arphdr->sha, MAC_LEN);
    memcpy(arphdr->sha, tmp_mac, MAC_LEN);
    memcpy(ethhdr->ether_dhost, arphdr->tha, MAC_LEN);
    memcpy(ethhdr->ether_shost, arphdr->sha, MAC_LEN);

    // changing opcode
    arphdr->op = htons(ARPOP_REPLY);
    send_to_link(interface, buf, len);
}
