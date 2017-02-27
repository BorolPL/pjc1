#include "naglowki.h"
#include "lwiazane.h"
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>


unsigned short zamianaShort(unsigned short a){
	short b;
	b=((a & 0xff00) >>8) | ((a & 0x00ff) << 8);
	return b;
}


void upakuj_eth_arp (unsigned char *bufor_eth_arp, struct eth_arp *pakiet_arp, int size){
	memcpy(pakiet_arp,bufor_eth_arp,size);

	pakiet_arp->nagl_eth.typ_protokolu = zamianaShort(pakiet_arp->nagl_eth.typ_protokolu);
	pakiet_arp->nagl_arp.Htype = zamianaShort(pakiet_arp->nagl_arp.Htype );
	pakiet_arp->nagl_arp.Ptype = zamianaShort(pakiet_arp->nagl_arp.Ptype);
	pakiet_arp->nagl_arp.opcode = zamianaShort(pakiet_arp->nagl_arp.opcode);
}

void upakuj_eth_ip_icmp(unsigned char *bufor_eth_ip_icmp, struct eth_ip_icmp *pakiet_icmp, int size){
	memcpy(pakiet_icmp,bufor_eth_ip_icmp,size);

	pakiet_icmp->nagl_eth.typ_protokolu = zamianaShort(pakiet_icmp->nagl_eth.typ_protokolu);
	pakiet_icmp->nagl_ip.calk_dlugosc = zamianaShort(pakiet_icmp->nagl_ip.calk_dlugosc);
	pakiet_icmp->nagl_ip.id = zamianaShort(pakiet_icmp->nagl_ip.id);
	pakiet_icmp->nagl_ip.suma_kontrolna = zamianaShort(pakiet_icmp->nagl_ip.suma_kontrolna);
	pakiet_icmp->nagl_icmp.suma_kontrolna = zamianaShort(pakiet_icmp->nagl_icmp.suma_kontrolna);
	pakiet_icmp->nagl_icmp.id = zamianaShort(pakiet_icmp->nagl_icmp.id);
	pakiet_icmp->nagl_icmp.numer_sekwencji = zamianaShort(pakiet_icmp->nagl_icmp.numer_sekwencji);
}

void upakuj_eth_ip_udp(unsigned char *bufor_eth_ip_udp, struct eth_ip_udp *pakiet_udp, int size){
	memcpy(pakiet_udp,bufor_eth_ip_udp,size);

	pakiet_udp->nagl_eth.typ_protokolu = zamianaShort(pakiet_udp->nagl_eth.typ_protokolu);
	pakiet_udp->nagl_ip.calk_dlugosc = zamianaShort(pakiet_udp->nagl_ip.calk_dlugosc);
	pakiet_udp->nagl_ip.id = zamianaShort(pakiet_udp->nagl_ip.id);
	pakiet_udp->nagl_ip.suma_kontrolna = zamianaShort(pakiet_udp->nagl_ip.suma_kontrolna);
	pakiet_udp->nagl_udp.zrodlowy_port = zamianaShort(pakiet_udp->nagl_udp.zrodlowy_port);
	pakiet_udp->nagl_udp.docelowy_port = zamianaShort(pakiet_udp->nagl_udp.docelowy_port);
	pakiet_udp->nagl_udp.dlugosc = zamianaShort(pakiet_udp->nagl_udp.dlugosc);
	pakiet_udp->nagl_udp.suma_kontrolna = zamianaShort(pakiet_udp->nagl_udp.suma_kontrolna);

}

void upakuj_eth_ip_tcp(unsigned char *bufor_eth_ip_tcp, struct eth_ip_tcp *pakiet_tcp, int size){
	memcpy(pakiet_tcp,bufor_eth_ip_tcp,size);

	pakiet_tcp->nagl_eth.typ_protokolu = zamianaShort(pakiet_tcp->nagl_eth.typ_protokolu);
	pakiet_tcp->nagl_ip.calk_dlugosc = zamianaShort(pakiet_tcp->nagl_ip.calk_dlugosc);
	pakiet_tcp->nagl_ip.id = zamianaShort(pakiet_tcp->nagl_ip.id);
	pakiet_tcp->nagl_ip.suma_kontrolna = zamianaShort(pakiet_tcp->nagl_ip.suma_kontrolna);
	pakiet_tcp->nagl_tcp.zrodlowy_port = zamianaShort(pakiet_tcp->nagl_tcp.zrodlowy_port);
	pakiet_tcp->nagl_tcp.docelowy_port = zamianaShort(pakiet_tcp->nagl_tcp.docelowy_port);
	pakiet_tcp->nagl_tcp.szerokosc_okna = zamianaShort(pakiet_tcp->nagl_tcp.szerokosc_okna);
	pakiet_tcp->nagl_tcp.suma_kontrolna = zamianaShort(pakiet_tcp->nagl_tcp.suma_kontrolna);
	pakiet_tcp->nagl_tcp.wskaznik_priorytetu = zamianaShort(pakiet_tcp->nagl_tcp.wskaznik_priorytetu);
	pakiet_tcp->nagl_tcp.opcje[0] = zamianaShort(pakiet_tcp->nagl_tcp.opcje[0]);
	pakiet_tcp->nagl_tcp.opcje[1] = zamianaShort(pakiet_tcp->nagl_tcp.opcje[1]);
}


struct lista_arp *firstArp = NULL;
struct lista_arp *lastArp = NULL;

struct lista_tcp *firstTcp = NULL;
struct lista_tcp *lastTcp = NULL;

struct lista_udp *firstUdp = NULL;
struct lista_udp *lastUdp = NULL;

struct lista_icmp *firstIcmp = NULL;
struct lista_icmp *lastIcmp = NULL;

int dodaj_do_listy_ARP(struct eth_arp packet) {//alokowanie pakietow w liscie wiazanej
	struct lista_arp *new;

	new = (struct lista_arp *) malloc(sizeof(struct lista_arp));

	new->packet = packet;

	if (firstArp == NULL) {
		firstArp = new;
		lastArp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastArp;
		new->next = NULL;
		lastArp->next = new;
		lastArp = new;
	}
	return 0;
}

int czyszczenie_listy_ARP(struct lista_arp *element) {// nullowanie calej listy
	if (element == NULL) {
		return -1;
	}
	if (firstArp != lastArp) {
		firstArp = firstArp->next;
		firstArp->back = NULL;
		free(element);
	} else {
		free(element);
		firstArp = NULL;
		lastArp= NULL;
	}
	return 0;
}

void przygotuj_pakiet_ARP(struct eth_arp *packet) {//przygotowanie pakietu do wyslania zmieniajac adresy mac
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy(&packet->nagl_eth.docelowy_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	memcpy(&packet->nagl_eth.zrodlowy_mac, &tmpDstMac, 6);
}

void wyslij_pakiet_ARP(struct eth_arp *packet) {//wysylanie przygotowanego pakietu
	char *ether = (char *) malloc(1514);

	memcpy(ether, packet, sizeof(struct eth_arp));


	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6]={00,00,00,00,00,00};
	//memcpy(&src_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6]={11,11,11,11,11,11};
	//memcpy(&dest_mac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0806); //Protokol warstwy wyzszej: 0x0806 - pakiet arp

	memcpy(data, ether + 14, sizeof(struct eth_arp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		printf ("\twysyłanie ramek ARP\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_ARP() {//sklada dwie funkcje: przygotowania i wyslania pakietu
	int x = 0;
	struct lista_arp *tmp = firstArp;
	while (tmp != NULL) {
		x++;
		przygotuj_pakiet_ARP(&tmp->packet);
		wyslij_pakiet_ARP(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			czyszczenie_listy_ARP(tmp->back);
		} else {
			czyszczenie_listy_ARP(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

int dodaj_do_listy_IP_ICMP(struct eth_ip_icmp packet) {//alokowanie pakietow w liscie wiazanej

	struct lista_icmp *new;

	new = (struct lista_icmp *) malloc(sizeof(struct lista_icmp));

	new->packet = packet;

	if (firstIcmp == NULL) {
		firstIcmp = new;
		lastIcmp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastIcmp;
		new->next = NULL;
		lastIcmp->next = new;
		lastIcmp = new;
	}
	return 0;
}

int czyszczenie_listy_IP_ICMP(struct lista_icmp *element) {// nullowanie calej listy
	if (element == NULL) {
		return -1;
	}
	if (firstIcmp != lastIcmp) {
		firstIcmp = firstIcmp->next;
		firstIcmp->back = NULL;
		free(element);
	} else {
		free(element);
		firstIcmp = NULL;
		lastIcmp = NULL;
	}
	return 0;
}

void przygotuj_pakiet_IP_ICMP(struct eth_ip_icmp *packet) {//przygotowanie pakietu do wyslania zmieniajac adresy mac
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy(&packet->nagl_eth.docelowy_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	memcpy(&packet->nagl_eth.zrodlowy_mac, &tmpDstMac, 6);
}

void wyslij_pakiet_IP_ICMP(struct eth_ip_icmp *packet) {//wysylanie przygotowanego pakietu
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(struct eth_ip_icmp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0800); //Protokol warstwy wyzszej: 0x0806 - pakiet ip4

	memcpy(data, ether + 14, sizeof(struct eth_ip_icmp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	printf ("\twysylanie ramek ICMP\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_IP_ICMP() {//sklada dwie funkcje: przygotowania i wyslania pakietu
	int x = 0;
	struct lista_icmp *tmp = firstIcmp;
	while (tmp != NULL) {
		x++;
		przygotuj_pakiet_IP_ICMP(&tmp->packet);
		wyslij_pakiet_IP_ICMP(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			czyszczenie_listy_IP_ICMP(tmp->back);
		} else {
			czyszczenie_listy_IP_ICMP(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

int dodaj_do_listy_IP_UDP(struct eth_ip_udp packet) {//alokowanie pakietow w liscie wiazanej
	struct lista_udp *new;

	new = (struct lista_udp *) malloc(sizeof(struct lista_udp));

	new->packet = packet;

	if (firstUdp == NULL) {
		firstUdp = new;
		lastUdp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastUdp;
		new->next = NULL;
		lastUdp->next = new;
		lastUdp = new;
	}
	return 0;
}

int czyszczenie_listy_IP_UDP(struct lista_udp *element) {// nullowanie calej listy
	if (element == NULL) {
		return -1;
	}
	if (firstUdp != lastUdp) {
		firstUdp = firstUdp->next;
		firstUdp->back = NULL;
		free(element);
	} else {
		free(element);
		firstUdp = NULL;
		lastUdp = NULL;
	}
	return 0;
}

void przygotuj_pakiet_IP_UDP(struct eth_ip_udp *packet) {//przygotowanie pakietu do wyslania zmieniajac adresy mac
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy(&packet->nagl_eth.docelowy_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	memcpy(&packet->nagl_eth.zrodlowy_mac, &tmpDstMac, 6);
}

void wyslij_pakiet_IP_UDP(struct eth_ip_udp *packet) {//wysylanie przygotowanego pakietu
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(struct eth_ip_udp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet ipv4

	memcpy(data, ether + 14, sizeof(struct eth_ip_udp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	printf ("\twysylanie ramek UDP\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_IP_UDP() {//sklada dwie funkcje: przygotowania i wyslania pakietu
	int x = 0;
	struct lista_udp *tmp = firstUdp;
	while (tmp != NULL) {
		x++;
		przygotuj_pakiet_IP_UDP(&tmp->packet);
		wyslij_pakiet_IP_UDP(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			czyszczenie_listy_IP_UDP(tmp->back);
		} else {
			czyszczenie_listy_IP_UDP(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}

int dodaj_do_listy_IP_TCP(struct eth_ip_tcp packet) {//alokowanie pakietow w liscie wiazanej
	struct lista_tcp *new;

	new = (struct lista_tcp *) malloc(sizeof(struct lista_tcp));

	new->packet = packet;

	if (firstTcp == NULL) {
		firstTcp = new;
		lastTcp = new;
		new->next = NULL;
		new->back = NULL;
	} else {
		new->back = lastTcp;
		new->next = NULL;
		lastTcp->next = new;
		lastTcp = new;
	}
	return 0;
}

int czyszczenie_listy_IP_TCP(struct lista_tcp *element) {// nullowanie calej listy
	if (element == NULL) {
		return -1;
	}
	if (firstTcp != lastTcp) {
		firstTcp = firstTcp->next;
		firstTcp->back = NULL;
		free(element);
	} else {
		free(element);
		firstTcp = NULL;
		lastTcp = NULL;
	}

	return 0;
}

void przygotuj_IP_TCP(struct eth_ip_tcp *packet) { //przygotowanie pakietu do wyslania zmieniajac adresy mac
	char tmpDstMac[6];
	memcpy(&tmpDstMac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy(&packet->nagl_eth.docelowy_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	memcpy(&packet->nagl_eth.zrodlowy_mac, &tmpDstMac, 6);
}

void wyslij_pakiet_IP_TCP(struct eth_ip_tcp *packet) {//wysylanie przygotowanego pakietu
	char *ether = (char *) malloc(1514);
	memcpy(ether, packet, sizeof(struct eth_ip_tcp));

	int s_out; /*deskryptor gniazda*/

	//bufor dla ramek z Ethernetu
	void* buffer = (void*) malloc(ETH_FRAME_LEN);
	//wskaxnik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	//inny wskaznik do naglowka Eth
	struct ethhdr *eh = (struct ethhdr *) etherhead;
	//adres docelowy
	struct sockaddr_ll socket_address;
	int send_result = 0;
	struct ifreq ifr;
	int ifindex = 0;

	socket_address.sll_halen = ETH_ALEN;

	///////////////////Ustaw naglowek ramki///////////////////////////////////////
	//Adres zrodlowy Eth
	unsigned char src_mac[6];
	memcpy(&src_mac, &packet->nagl_eth.zrodlowy_mac, 6);
	//Adres docelowy Eth
	unsigned char dest_mac[6];
	memcpy(&dest_mac, &packet->nagl_eth.docelowy_mac, 6);
	memcpy((void*) buffer, (void*) dest_mac, ETH_ALEN);
	memcpy((void*) (buffer + ETH_ALEN), (void*) src_mac, ETH_ALEN);
	eh->h_proto = htons(0x0800); //Protokol warstwy wyzszej: 0x0806 - pakiet arp

	memcpy(data, ether + 14, sizeof(struct eth_ip_tcp) - 14);

	//**************************wyslij ramke***********************************

	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
	printf ("\twysylanie ramek TCP\n");
	if (s_out == -1) {
		printf("Nie moge otworzyc gniazda s_out\n");
	}

	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;
	printf("Pobrano indeks karty NIC: %i\n", ifindex);
	socket_address.sll_ifindex = ifindex;

	send_result = sendto(s_out, buffer, 1514, 0,
			(struct sockaddr*) &socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Nie moge wyslac danych! \n");
	} else {
		printf("Wyslalem dane do intefejsu: %s \n", INTERFACE);
	}
}

void wyslij_IP_TCP() {//sklada dwie funkcje: przygotowania i wyslania pakietu
	int x = 0;
	struct lista_tcp *tmp = firstTcp;
	while (tmp != NULL) {
		x++;
		przygotuj_IP_TCP(&tmp->packet);
		wyslij_pakiet_IP_TCP(&tmp->packet);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			czyszczenie_listy_IP_TCP(tmp->back);
		} else {
			czyszczenie_listy_IP_TCP(tmp);
			tmp = NULL;
		}
		printf("\nwyslano %d pakiet\n", x);
	}
}


