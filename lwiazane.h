#ifndef LWIAZANE_H_
#define LWIAZANE_H_

#include "naglowki.h"
#define INTERFACE "eth0"

struct lista_arp{
	struct eth_arp packet;
	struct lista_arp *next;
	struct lista_arp *back;
};


struct lista_tcp {
	struct eth_ip_tcp packet;
	struct lista_tcp *next;
	struct lista_tcp *back;
};


struct lista_udp {
	struct eth_ip_udp packet;
	struct lista_udp *next;
	struct lista_udp *back;
};


struct lista_icmp {
	struct eth_ip_icmp packet;
	struct lista_icmp *next;
	struct lista_icmp *back;
};

void upakuj_eth_arp (unsigned char *bufor_eth_arp, struct eth_arp *pakiet_arp, int size);
void upakuj_eth_ip_icmp(unsigned char *bufor_eth_ip_icmp, struct eth_ip_icmp *pakiet_icmp, int size);
void upakuj_eth_ip_udp(unsigned char *bufor_eth_ip_udp, struct eth_ip_udp *pakiet_udp, int size);
void upakuj_eth_ip_tcp(unsigned char *bufor_eth_ip_tcp, struct eth_ip_tcp *pakiet_tcp, int size);

int dodaj_do_listy_ARP(struct eth_arp packet);
int dodaj_do_listy_IP_ICMP(struct eth_ip_icmp packet);
int dodaj_do_listy_IP_UDP(struct eth_ip_udp packet);
int dodaj_do_listy_IP_TCP(struct eth_ip_tcp packet);

void wyslij_ARP();
void wyslij_IP_ICMP();
void wyslij_IP_UDP();
void wyslij_IP_TCP();


#endif /* LWIAZANE_H_ */
