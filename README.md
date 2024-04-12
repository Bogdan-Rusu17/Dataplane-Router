*COPYRIGHT RUSU BOGDAN, 322CA, 2023-2024*

# Dataplane Router, Communication Protocols Project

The purpose of this project was to implement the `Dataplane` part of a router's software, having already been given the `Control plane` logic, e.g. `routing tables` already populated by specific algorithms.

The `Dataplane` logic consists of the `forwarding process`, whose functionality is based on the `layer 3` (Network) and `layer 2` (Datalink) protocols.

The `router` is conceptually seen as an `entity` which has `multiple interfaces`, each of which having its own `IP address` and `MAC address`. Packets can flow into the `router` through one of those interfaces using the `API` provided by the `recv_from_any_link()` function.

The `flow` of data through the router will be presented below, but, first off, a `problem` that occurs whenever an entity is searching through `large amounts` of data is the time efficiency. In this case, the router must find for `each incoming packet` the best router to transmit it further. To satisfy this need, the `routing table` (in this project already populated and dumped into the `rtable` array using the `read_rtable()` API function) must be `interogated` for each incoming packet. Such `interogations` can become costly (e.g. a `linear search` in the routing table), and as such a more efficient approach must be employed. Such a strategy involves the usage of a `binary trie` for `efficient` routing table querries.

The `binary trie` data structure is an `arborescent` entity that uses `trie_nodes` each having at most 2 children (in the implementation, an `array consisting of 2 pointers` to children nodes), and a pointer to a `routing_table_entry`.

A `routing_table_entry` is represented as having the following members:
* `prefix IP`
* `nextHop Ip`
* `mask`
* `nextHopInterface`

The `prefix IP` and `mask` dictate whether a `target IP` matches this `route` by verifying the condition:
```c
if (prefix == (targetIP & mask))
    // good route
```

The `2 main` functionalities this `binary trie` must implement are the following:
* `insertion` of a route into the trie: for each of the bits of the mask, we create a `new trie node` corresponding to the bit (0 or 1) of the prefix and link it to the `current parent node`; whenever the `final bit` of the prefix is reached, the pointer of the node to the `route_table_entry` is set to point to the given `route_table_entry` parameter whilst the rest are set to `NULL`

* `querrying` to find the `best route` for a `nextHopIP`: for each bit of the `nextHopIP` we find `which child` of the current root to go to (0 or 1); whenever we traverse the `trie`, the pointer in each node traversed is stored in a pointer named `match` and thus at the end of the traversal, it is known for sure that the `most specific match` route_table_entry is stored in the `match` pointer variable


In `each iteration` of the router program loop, the router waits to receive a packet on `one` of its `interfaces`.

For this project, the packets received can only be of type `Ethernet` at the `Datalink` level.

Whenever the router receives a packet, the `ethernet header` is extracted with `pointer arithmetic` and we have `2 situations`:
* The `ether_type` of the header is `ETHERTYPE_IP` (0x0800), we have to process a packet whose `level 3 (Network)` protocol is the `Internet protocol`:
    * if the `destination field` of the `IP header` is exactly the IP of the interface the packet was received on, then the packet contains an `ICMP Echo Request`, and the router must respond back with an `ICMP Echo Reply` -> for that end, the buffer received is modified so as to `swap` the `ip->daddr` and `ip-saddr` addresses (the receiver becomes the sender and vice versa) and the same thing for the `dhost` and `shost` fields in the `Ethernet header`, also the `ECHO ICMP reply` uses `code = 0` and `type = 0` for identification

    * if the router is not the destination, then the `checksum` must be `evaluated`  again to make sure the data in the `ip_header` was not corrupted; if it was then the packet is `dropped` (aka `continue` is called to enter the while loop again so as to wait for the `next packet` the router will receive)

    * if the `checksum` was good, then the `time-to-live` field in the `ip_header` is decremented and checked against it `being 0` -> if the `ttl` would be 0 after decrementation, then the rotuer must send and `ICMP TLE Reply`
        * a `new packet` is constructed for the router to send to the interface it received the `original packet` from (making sure the `ether header` and `ip header` are constructed accordingly, swapping `destination` and `sender` like above), marking the `code` and `type` field of the `icmp header` accordingly (0, 11 respectively) and fills the buffer to be sent with the `IP header` of the `received packet` and the first `8 bytes` of the payload of the original packet IP Header
    * if `time-to-live` was enough to pass to the next hop, we querry the `binary trie routing table` to find out which `nextHopIP` and `interface` to send the packet to
        * if no available route is found in the `binary trie routing table`, the router must send an `ICMP Destination Unreachable Reply` akin to the `TLE reply`, only modification lying in the type (`3` for `Dest Unreachable`)
    * if a route to transmit the packet forward is found, then we must interogate the dinamically build `arp_table` (each entry containing a pair of `IP` and `MAC` meaning to go to the entry's IP, the packet must be physically sent to the entry's `MAC Address`)
        * if such a correspondence is found for the `best route` then the packet is simply sent, with updated `MAC addresses`, through the interface contained in the best_route found
    * if no `MAC` address corresponding to the `NextHopIp` is found, then the router must send an `ARP_Request` to find the `MAC` address of the `nextHopIP`
        * a new packet is constructed (`Ethernet` for layer 2 protocol and `ARP` for the layer 3 protocol)
        * the `ARP` protocol essentially specifies the mac address of the sender, `sha`, ip address of the sender `spa`, ip address of the target `tpa` and the `tha` (target hardware address) is built to be 0xffffffffffff (meaning broadcast) -> the request essentially asks: Who has the IP `tpa` ? Tell (`spa`, `sha`)
        * while waiting for the `ARP reply`, the packet is enqued along with the interface it was received on and its length
    
* The `ether_type` of the header is `ETHERTYPE_ARP` (0x0806), we have to process a packet whose `level 3 (Network)` protocol is the `Address resolution Protocol`:
    * if the `op` field of the `ARP packet` is:
        * `ARPOP REPLY` means the router has received a reply for the above formulated request and can dequeue all the packets that were waiting to be send on the `mac` address received from the `arp reply` and sent and the remaining ones are put in a new queue
        * `ARPOP REQUEST` means the router has received a request for its `IP` and will construct an `ARP Reply`, swapping the positions of sender and target, and putting into the `sha` its own `MAC address` (the one corresponding to the interface it had received the `ARP Request`)