#include <queue.h>
#include "skel.h"

struct route_table_entry *rtable;
int rtable_size;
struct arp_entry *arp_table;
int arp_table_size;

// returneaza un pointer la adresa cea mai asemanatoare pentru adresa destinatie 
//primita ca parametru (asemanatoare cu functia "get_nei_entry" din laboratorul 4)
struct arp_entry *get_arp_entry(uint32_t ip_addr) {
	for (int i = 0; i < arp_table_size; i++) {
		if (arp_table[i].ip == ip_addr) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int cmp(const void *rt1, const void *rt2) {

	struct route_table_entry rt_entry1 = *(struct route_table_entry *)rt1;
	struct route_table_entry rt_entry2 = *(struct route_table_entry *)rt2;

	if (rt_entry2.prefix > rt_entry1.prefix) {
		return -1;
	}else{
		if (rt_entry2.prefix < rt_entry1.prefix) {
			return 1;
		}else{
			if (rt_entry2.prefix == rt_entry1.prefix) {
				if (rt_entry2.mask > rt_entry1.mask) {
					return -1;
				} else 
					return 1;
			}
		}	
	}
	return 1;
}

//  Cauta in tabela de rutare cea mai buna ruta catre destinatie
struct route_table_entry *binary_search_route(uint32_t daddr, int left, int right) {
    if (right >= left) {
        int mid = left + (right - left) / 2;

        if ((rtable[mid].mask & daddr) == rtable[mid].prefix) {
			uint32_t prefix = rtable[mid].prefix;
			while (rtable[mid].prefix == prefix) {
				mid++;
			}
			mid--;
			return &rtable[mid];
		}
        if ((rtable[mid].mask & daddr) < rtable[mid].prefix)
            return binary_search_route(daddr, left, mid - 1);
		else
        	return binary_search_route(daddr, mid + 1, right);
    }
    return NULL;
}



int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	rtable_size = read_rtable(argv[1], rtable);

	arp_table = malloc(sizeof(struct arp_entry));
	arp_table_size = 0;
	queue q = queue_create();

	//Sortez adresele dupa prefix, apoi dupa masca
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_header = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
		

	//  Verificare pachete proprii
		if(icmp_header != NULL){
			if(icmp_header->type == ICMP_ECHO){
				if(ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))){
					//Construiesc struct ether_header
					struct ether_header aux_eth_hdr;
					memcpy(aux_eth_hdr.ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
					memcpy(aux_eth_hdr.ether_shost, eth_hdr->ether_dhost, ETH_ALEN);
					aux_eth_hdr.ether_type = htons(ETHERTYPE_IP);

					//Construiesc struct iphdr
					struct iphdr aux_ip_hdr;
					create_ip_hdr(&aux_ip_hdr, ip_hdr->saddr, ip_hdr->daddr);

					//Construiesc struct icmphdr
					struct icmphdr aux_icmp_hdr;
					aux_icmp_hdr.type = 0;
					aux_icmp_hdr.code = 0;
					aux_icmp_hdr.checksum = 0;
					aux_icmp_hdr.un.echo.id = icmp_header->un.echo.id;
					aux_icmp_hdr.un.echo.sequence = icmp_header->un.echo.sequence;
					aux_icmp_hdr.checksum = icmp_checksum((uint16_t *)&aux_icmp_hdr, sizeof(struct icmphdr));
	
					//Construiesc pachetul
					packet packet;
					void *payload;
					payload = packet.payload;
					memcpy(payload, &aux_eth_hdr, sizeof(struct ether_header));
					payload += sizeof(struct ether_header);
					memcpy(payload, &aux_ip_hdr, sizeof(struct iphdr));
					payload += sizeof(struct iphdr);
					memcpy(payload, &aux_icmp_hdr, sizeof(struct icmphdr));
					packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

					(&packet)->interface = m.interface; 
					send_packet(&packet);
					continue;
				}
			}
		}


		struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

		if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {	
			// Pun adresa MAC in headerul Ethernet
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
			get_interface_mac(m.interface, eth_hdr->ether_shost);
			eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			// Construiesc un pachet pentru ARP REPLY
			struct arp_header aux_arp_hdr;
			packet packet;

			aux_arp_hdr.htype = htons(ARPHRD_ETHER);
			aux_arp_hdr.ptype = htons(2048);
			aux_arp_hdr.op = htons(ARPOP_REPLY);
			aux_arp_hdr.hlen = 6;
			aux_arp_hdr.plen = 4;
			memcpy(aux_arp_hdr.sha, eth_hdr->ether_shost, 6);
			memcpy(aux_arp_hdr.tha, eth_hdr->ether_dhost, 6);
			aux_arp_hdr.spa = inet_addr(get_interface_ip(m.interface));
			aux_arp_hdr.tpa = arp_hdr->spa;
			memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
			memcpy(packet.payload + sizeof(struct ethhdr), &aux_arp_hdr, sizeof(struct arp_header));
			packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);

			(&packet)->interface = m.interface; 
			send_packet(&packet);
			continue;
		}

		// 4. Parseaza ARP REPLY
		if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
			// Adaugare in cache local
			arp_table = realloc(arp_table, sizeof(struct route_table_entry) * (arp_table_size + 1));
			arp_table_size++;
			memcpy(arp_table[arp_table_size - 1].mac, arp_hdr->sha, ETHER_ADDR_LEN);
			arp_table[arp_table_size - 1].ip = arp_hdr->spa;
				
			// Trimit pachetele din coada pentru care adresa urmatorului hop este cunoscuta
			if(queue_empty(q))
				continue;
			else{
				while (!queue_empty(q)) {
					packet *deq_pac = (packet *)queue_deq(q);
					struct ether_header *deq_eth_hdr = (struct ether_header *)deq_pac->payload;
					struct iphdr *deq_ip_hdr = (struct iphdr *)(deq_pac->payload + sizeof(struct ether_header));
					struct route_table_entry *new_pac = binary_search_route(deq_ip_hdr->daddr, 0, rtable_size - 1);
					if (arp_hdr->spa == (new_pac->next_hop)) { // Daca adresa urmatorului hop este cunoscuta
						get_interface_mac(new_pac->interface, deq_eth_hdr->ether_shost);
						memcpy(deq_eth_hdr->ether_dhost, arp_hdr->sha, ETHER_ADDR_LEN);
						deq_eth_hdr->ether_type = htons(ETHERTYPE_IP);
						deq_pac->interface = new_pac->interface;
						send_packet(deq_pac);
					}
				}
			}
			continue;
		}
	

	//  Verificare checksum
		uint16_t initial_checksum = ip_hdr->check;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
		if (ip_hdr->check != initial_checksum) {
		 	continue;
	 }

	//  Verifixare si actualizare TTL
		if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) { // eroare ICMP "Time exceeded"
			packet packet;
			create_icmp_error(&packet, ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11);
			(&packet)->interface = m.interface; 
			send_packet(&packet);	
			continue;
		}else{	// Decrementare camp TTL
			(ip_hdr->ttl)--;
		}


	//  Cautare in tabela de rutare cea mai buna ruta catre destinatie
		struct route_table_entry *best_route = binary_search_route( ip_hdr->daddr, 0, rtable_size - 1);
		if (best_route == NULL) { //eroare ICMP "Destination Unreachable"
			packet packet;
			create_icmp_error(&packet, ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 3);
			(&packet)->interface = m.interface; 
			send_packet(&packet);	
			continue;
		}

	//  Actualizare checksum
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));


	//  Cautarea in cache a adresei MAC corespunzatoare adresei IP a uramtorului hop
		struct arp_entry *dest_MAC_adress = get_arp_entry(best_route->next_hop);
		if(dest_MAC_adress != NULL){
			// Actualizare pachet cu noua adresa destinatie
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, dest_MAC_adress->mac, ETHER_ADDR_LEN);

			//  Trimiterea noului pachet pe interfata corespunzatoare
			(&m)->interface = best_route->interface;
			send_packet(&m);

		}else{// daca nu este gasita adresa MAC destinatie
			 // Pune pachetul in coada pentru a fi trimis cand este primita adresa
			// MAC a destinatarului
			packet *aux_pac = malloc(sizeof(packet));
			memcpy(aux_pac->payload, m.payload, sizeof(m.payload));
			aux_pac->len = m.len;
			aux_pac->interface = m.interface;
			queue_enq(q, aux_pac);
			
			//  Generare ARP REQUEST
			//Creez adresa MAC destinatie a pachetului de tip ARP REQUEST; 
			//este adresa de Broadcast FF:FF:FF:FF:FF:FF
			uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};
			memcpy(eth_hdr->ether_dhost, broadcast, 6);
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			// Construiesc un pachet pentru ARP REQUEST
			struct arp_header aux_arp_hdr;
			packet packet;

			aux_arp_hdr.htype = htons(ARPHRD_ETHER);
			aux_arp_hdr.ptype = htons(2048);
			aux_arp_hdr.op = htons(ARPOP_REQUEST);
			aux_arp_hdr.hlen = 6;
			aux_arp_hdr.plen = 4;
			memcpy(aux_arp_hdr.sha, eth_hdr->ether_shost, 6);
			memcpy(aux_arp_hdr.tha, eth_hdr->ether_dhost, 6);
			aux_arp_hdr.spa = inet_addr(get_interface_ip(best_route->interface));
			aux_arp_hdr.tpa = best_route->next_hop;
			memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
			memcpy(packet.payload + sizeof(struct ethhdr), &aux_arp_hdr, sizeof(struct arp_header));
			packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);

			(&packet)->interface = best_route->interface; 
			send_packet(&packet);
			continue;
		}
	}
}
