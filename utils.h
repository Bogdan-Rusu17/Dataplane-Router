#ifndef _UTILS_H_
#define _UTILS_H_ 1

#include <string.h>
#include "include/lib.h"
#include "include/protocols.h"
#include "stdlib.h"
#include "arpa/inet.h"

#define MAC_LEN 6
#define IP_LEN 4
#define PACKAGE_MAX_LEN 2000

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

typedef struct package {
    char *buf;
    size_t len;
    int interface;
} package;

void send_icmp_echo_reply(int interface, char *pack, size_t pack_len);
void send_icmp_tle_reply(int interface, char *pack, size_t pack_len);
void send_icmp_dest_unreachable_reply(int interface, char *pack, size_t pack_len);
struct arp_table_entry *get_arp_entry_by_ip(struct arp_table_entry *arp_table,
                                           int arp_table_len,
                                           struct route_table_entry *best_route);
void send_arp_request(struct route_table_entry *best_route,
                      int interface,
                      char *pack,
                      size_t pack_len);
void send_arp_reply(char *buf, int interface, size_t len);
#endif  // _UTILS_H
