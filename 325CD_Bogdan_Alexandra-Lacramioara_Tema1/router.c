

/* Pentru realizarea acestei teme am folosit 2 sleep days */

#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define  ETH_ALEN 6 
#define ARPHRD_ETHER 1
#define ETH_P_IP 2048 

typedef struct {

    int interface;
    char payload[MAX_PACKET_LEN];
    size_t len;

} queue_packet;

/* Arp table */
struct arp_entry *arp_table;
int arptable_len;

 queue q;

/* Recursive binary search function */

int binary_search(int left, int right, uint32_t prefix, uint32_t mask, uint32_t dest) {
    
    if (left > right) {
        return -1;
    }

    int mid = (left + right) / 2;

    if ((prefix & mask) == (dest & mask)) {
        return mid;
    }

    if ((prefix & mask) > (dest & mask)) {
        return binary_search(left, mid - 1, prefix, mask, dest);
    }

    return binary_search(mid + 1, right, prefix, mask, dest);
}

/* Search best route in O(logn) */

struct route_table_entry *search_best_route(struct route_table_entry *rtable, int rtable_len , struct in_addr dest_ip) {
    struct route_table_entry *best = NULL;

    int position = binary_search(0, rtable_len, 0, 0, dest_ip.s_addr);

    if (position == -1) {
        return NULL;
    }

    uint32_t dest = dest_ip.s_addr;

    while (position >= 0) {
        struct route_table_entry *entry = &rtable[position];

        if ((dest & entry->mask) == entry->prefix) {
            if (best == NULL || (entry->mask > best->mask)) {
                best = entry;
            }
        }

        position--;
    }

    return best;
}


void build_eth_header(struct ether_header *eth_hdr) {

    uint8_t aux[6];
    memcpy(aux, eth_hdr->ether_dhost, 6);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, aux, 6);
    eth_hdr->ether_type = htons(0x0800);

}

void build_ip_header(struct iphdr *ip_hdr) {

    uint32_t aux_addr = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = aux_addr;

    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->ihl = 5;
    ip_hdr->id = htons(getpid()); 
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_ICMP;

    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
}


void build_icmp(struct iphdr *ip_hdr, struct icmphdr *icmp, struct ether_header *eth_hdr,
     int interface, char buf[MAX_PACKET_LEN], size_t len, uint8_t type, uint8_t code ) {

    /* Construim eth_header */

    build_eth_header(eth_hdr);

    /* Construim ip_hdr */

    build_ip_header(ip_hdr);
    
    /* Construim Icmp */

    icmp->code = code;
    icmp->type = type;
    
    icmp->un.echo.id=htons(getpid());
    icmp->checksum=0;
    icmp->checksum=checksum((uint16_t *)icmp, sizeof(struct icmphdr));
}


int compare_routes(const void *a, const void *b) {

    const struct route_table_entry *route_a = (const struct route_table_entry *)a;
    const struct route_table_entry *route_b = (const struct route_table_entry *)b;

    if (route_a->prefix < route_b->prefix) {
        return -1;
    } else if (route_a->prefix > route_b->prefix) {
        return 1;
    } else {
        return 0;
    }
}


void handle_arp_request(struct arp_header *arph, struct ether_header *eth_hdr, int interface, char *buf, int len) {
    // Extract the target IP address from the ARP header
    struct in_addr target_ip;
    target_ip.s_addr = arph->tpa;

    // Get the IP address of the interface
    struct in_addr interface_ip;
    interface_ip.s_addr = inet_addr(get_interface_ip(interface));

    // If the target IP address matches the interface IP address, construct an ARP reply
    if (memcmp(&target_ip, &interface_ip, sizeof(struct in_addr)) == 0) {
        // Update the ARP header fields for the reply
        arph->op = htons(2);
        memcpy(arph->tha, arph->sha, ETH_ALEN);
        uint8_t mac[6];
        get_interface_mac(interface, mac);
        memcpy(arph->sha, mac, ETH_ALEN);
        arph->tpa = arph->spa;
        arph->spa = interface_ip.s_addr;

        // Update the Ethernet header fields for the reply
        memcpy(eth_hdr->ether_dhost, arph->tha, ETH_ALEN);
        memcpy(eth_hdr->ether_shost, arph->sha, ETH_ALEN);

        // Send the ARP reply
        send_to_link(interface, buf, len);
    }
}

struct arp_entry *arp_entry(struct route_table_entry *best, struct arp_entry* arp_table, int arp_table_size) {
    for (int i = 0; i < arp_table_size; i++) {
        if (best->next_hop == arp_table[i].ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

 queue_packet *put_in_packet(int interface, char buf[MAX_PACKET_LEN], size_t len) {

    queue_packet *p = (queue_packet*)malloc(sizeof(queue_packet));
    p->len = len;
    p->interface = interface;
    memcpy(p->payload, buf, len);
    return p;
 }

  void arp_request(struct route_table_entry *route, int interface) {

    size_t eth_header_size = sizeof(struct ether_header);
    size_t arp_header_size = sizeof(struct arp_header);
    size_t packet_size = eth_header_size + arp_header_size;
    
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t source_mac[6];
    get_interface_mac(route->interface, source_mac);
    
    uint16_t ether_type = htons(0x0806);
    uint16_t htype = htons(1);
    uint16_t ptype = htons(2048);
    uint16_t op = htons(1);
    uint32_t source_ip = inet_addr(get_interface_ip(route->interface));
    uint32_t target_ip = route->next_hop;
    
    char* buf = (char*)malloc(packet_size);
    
    struct ether_header* eth_header = (struct ether_header*)buf;
    memcpy(eth_header->ether_dhost, broadcast_mac, 6 * sizeof(uint8_t));
    memcpy(eth_header->ether_shost, source_mac, 6 * sizeof(uint8_t));
    eth_header->ether_type = ether_type;
    
    struct arp_header* arp_header = (struct arp_header*)(buf + eth_header_size);
    arp_header->htype = htype;
    arp_header->ptype = ptype;
    arp_header->hlen = 6;
    arp_header->plen = 4;
    arp_header->op = op;
    memcpy(arp_header->sha, source_mac, 6 * sizeof(uint8_t));
    arp_header->spa = source_ip;
    memcpy(arp_header->tha, broadcast_mac, 6 * sizeof(uint8_t));
    arp_header->tpa = target_ip;

    send_to_link(interface, buf, packet_size);
    
    free(buf);
}


int main(int argc, char *argv[])

{
	char buf[MAX_PACKET_LEN];


	// Do not modify this line
	init(argc - 2, argv + 2);


	struct route_table_entry route_table[100000];
    int rtable_len = read_rtable(argv[1], route_table);

   
   arp_table = malloc(sizeof(struct arp_entry) * 100);
   DIE(arp_table == NULL, "memory");
	arptable_len = 0;

	qsort(route_table, rtable_len - 1, sizeof(struct route_table_entry) , compare_routes);

    q = queue_create();



	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
        struct arp_header *arph = ((void *) eth_hdr) + sizeof(struct ether_header);
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	    len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	 if (ntohs(eth_hdr->ether_type) == 0x0800) {


			/* Verificam daca pachetul este de tip ICMP */

			struct in_addr* addr = (struct in_addr*)malloc(sizeof(struct in_addr));
	        inet_aton(get_interface_ip(interface), addr);

	    	if(icmp->type == 8 && ip_hdr->daddr == addr->s_addr) {

				    build_icmp(ip_hdr, icmp, eth_hdr, interface,buf,len, 0, 0);
					send_to_link(interface, buf, len); 
		
			}

			
				/* Calculam noul checksum si verificam daca este corect */

			    uint16_t actual_checksum = ntohs(ip_hdr->check);
                ip_hdr->check = 0;
                uint16_t new_checksum = checksum((uint16_t *)ip_hdr , sizeof(struct iphdr));
               

                if (actual_checksum != new_checksum) {
                    continue;
                }

				/* Verificam ttl daca este 0 sau 1 */

				if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
            
	              build_icmp(ip_hdr, icmp, eth_hdr, interface,buf,len, 11, 0);
                  send_to_link(interface, buf, len);
                  continue;
                }


				/* Cautam cea mai buna ruta */

				struct in_addr dest_ip;
				dest_ip.s_addr = ip_hdr->daddr;
			
                struct route_table_entry *best = search_best_route(route_table , rtable_len, dest_ip);

                
				/* Nu am gasit nicicun router */

				 if(best == NULL) {
                     
                     build_icmp(ip_hdr, icmp, eth_hdr, interface,buf,len, 3, 0);
                     send_to_link(interface, buf, len);
					 continue;

				}
 
				/* Get arp entry */

			   	struct arp_entry *arp = arp_entry(best, arp_table, arptable_len);

                if(arp == NULL) {

                    queue_packet *p=put_in_packet(interface, buf, len);
                    queue_enq(q, p);
                    arp_request(best, best->interface);
                    continue;
                }


				/* Decrementam ttl si recalculam chesksum */

				ip_hdr->ttl--;

                uint16_t recalculated_check = 0;
                recalculated_check = checksum((uint16_t *)ip_hdr , sizeof(struct iphdr));
                ip_hdr->check = 0;
                ip_hdr->check = ntohs(recalculated_check);

				memcpy(eth_hdr->ether_dhost, arp->mac, 6);
				get_interface_mac(best->interface, eth_hdr->ether_shost);

			    send_to_link(best->interface, buf , len);
                
                }


        /* Daca pachetul este ARP */
        
    else if (ntohs(eth_hdr->ether_type) == 0x0806) {

       
         if (ntohs(arph->op) == 1) {

             handle_arp_request(arph, eth_hdr, interface, buf, len);
                
         } 

         else if (ntohs(arph->op) == 2) {


            struct arp_entry *for_insertion = (struct arp_entry*)malloc(sizeof(struct arp_entry));
            for(int i = 0; i < 6; i++) {
                for_insertion->mac[i] = eth_hdr->ether_shost[i];
            }
            for_insertion->ip = arph->spa;


            memcpy(&arp_table[arptable_len], for_insertion, sizeof(struct arp_entry));
            arptable_len++;

            while(queue_empty(q) == 0)
             {

                queue_packet *dequeue_p = (queue_packet*)calloc(1, sizeof(queue_packet));

                dequeue_p = (queue_packet*)queue_deq(q);

	
			    struct ether_header *new_eth_hdr = (struct ether_header*)dequeue_p->payload;
                struct iphdr *packet_iph = ((void *) new_eth_hdr) + sizeof(struct ether_header);

                struct in_addr dest_ip;
                dest_ip.s_addr = packet_iph->daddr;

			    struct route_table_entry *route = search_best_route(route_table, rtable_len , dest_ip);

                if(route == NULL) { 
                    
                    build_icmp(packet_iph, icmp, new_eth_hdr, dequeue_p->interface, dequeue_p->payload, dequeue_p->len, 3, 0);
                    continue; 
                }


                struct arp_entry *arp = arp_entry(route, arp_table,arptable_len);
            
                memcpy(new_eth_hdr->ether_dhost, arp->mac, ETH_ALEN);
                dequeue_p->interface = route->interface;

                send_to_link(dequeue_p->interface, dequeue_p->payload, dequeue_p->len);

		    }
    }

  
    }

   }

   free(route_table);
   free(arp_table);
   free(q);
   
}