	#ifdef HAVE_CONFIG_H
	#include <config.h>
	#endif

	#include <stdio.h>
	#include <stdlib.h>

	#include <sys/socket.h>
	#include <linux/if_packet.h>
	#include <linux/if_ether.h>
	#include <linux/if_arp.h>
	#include "naglowki.h"
	#include "lwiazane.h"

	#define ETH_FRAME_LEN 1518


int main(void) {
	
	//definicja zmiennych
	int s; /*deskryptor gniazda*/
	int j;
	int i = 0;
	int length = 0;
	unsigned char bufor[ETH_FRAME_LEN];




	// deklaracja zmiennych - pakietow
	struct eth_ip_icmp 		pakiet_icmp;
	struct eth_ip_udp 		pakiet_udp;
	struct eth_ip_tcp 		pakiet_tcp;
	struct eth_arp 			pakiet_arp;



	//bufor dla ramek z Ethernetu
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	//wskaznik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;

	printf("Program do odbierania ramek Ethernet z NIC\n");

	//otworz gniazdo
	s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (s == -1) {printf ("Nie mozna otworzyc gniazda\n");}
int k;
	while (i<1) {
		for (k=0; k<10; k++){


		//odbierz ramke Eth
		length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if (length == -1)
			printf ("Problem z odbiorem ramki \n");
		else {
			i++;
			printf ("Ramka: %d, dlugosc: %d [B]\n", i, length);
		}

		#if 1
		//wypisz zawartosc bufora
			for (j=0;j<length; j++) {
				bufor[j] = *(etherhead+j);
//				printf ("%02x ", *(etherhead+j));
//				printf ("%02x ", bufor[j]);
			}
#endif

			if((bufor[12] == 8) && (bufor[13]== 6)){
				printf("to jest ethernet/arp\n\n========================\n"); //to jest ethernet/arp
				upakuj_eth_arp (&bufor, &pakiet_arp, sizeof(struct eth_arp));

					printf("DATAGRAM ETH/ARP\n\n");
					printf("\nNAGLOWEK ETHERNET\n\n"); //naglowek ETHERNET
					printf("Docelowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_arp.nagl_eth.docelowy_mac[0], pakiet_arp.nagl_eth.docelowy_mac[1], pakiet_arp.nagl_eth.docelowy_mac[2], pakiet_arp.nagl_eth.docelowy_mac[3], pakiet_arp.nagl_eth.docelowy_mac[4], pakiet_arp.nagl_eth.docelowy_mac[5]);
					printf("Zrodlowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_arp.nagl_eth.zrodlowy_mac[0], pakiet_arp.nagl_eth.zrodlowy_mac[1], pakiet_arp.nagl_eth.zrodlowy_mac[2], pakiet_arp.nagl_eth.zrodlowy_mac[3], pakiet_arp.nagl_eth.zrodlowy_mac[4], pakiet_arp.nagl_eth.zrodlowy_mac[5]);
					printf("Typ protokołu:\t%x\n", pakiet_arp.nagl_eth.typ_protokolu);

					printf("\nNAGLOWEK ARP\n\n");
					printf("Htype: %x\n",pakiet_arp.nagl_arp.Htype);
					printf("Ptype: %x\n",pakiet_arp.nagl_arp.Ptype);
					printf("Dlugosc adresu MAC: %02x\n",pakiet_arp.nagl_arp.dlugosc_mac);
					printf("Dlugosc IP: %02x\n",pakiet_arp.nagl_arp.dlugosc_ip);
					printf("Opcode: %x\n",pakiet_arp.nagl_arp.opcode);
					printf("Zrodlowy MAC: %02x %02x %02x %02x %02x %02x\n",pakiet_arp.nagl_arp.zrodlowyMAC[0], pakiet_arp.nagl_arp.zrodlowyMAC[1], pakiet_arp.nagl_arp.zrodlowyMAC[2], pakiet_arp.nagl_arp.zrodlowyMAC[3], pakiet_arp.nagl_arp.zrodlowyMAC[4], pakiet_arp.nagl_arp.zrodlowyMAC[5]);
					printf("Zrodlowy IP: %d.%d.%d.%d\n",pakiet_arp.nagl_arp.zrodlowyIP[0], pakiet_arp.nagl_arp.zrodlowyIP[1], pakiet_arp.nagl_arp.zrodlowyIP[2], pakiet_arp.nagl_arp.zrodlowyIP[3]);
					printf("Docelowy MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",pakiet_arp.nagl_arp.docelowyMAC[0], pakiet_arp.nagl_arp.docelowyMAC[1], pakiet_arp.nagl_arp.docelowyMAC[2], pakiet_arp.nagl_arp.docelowyMAC[3], pakiet_arp.nagl_arp.docelowyMAC[4], pakiet_arp.nagl_arp.docelowyMAC[5]);
					printf("Docelowy IP: %d.%d.%d.%d\n\n",pakiet_arp.nagl_arp.docelowyIP[0], pakiet_arp.nagl_arp.docelowyIP[1], pakiet_arp.nagl_arp.docelowyIP[2], pakiet_arp.nagl_arp.docelowyIP[3]);
					dodaj_do_listy_ARP(pakiet_arp);
			}


			if((bufor[12] == 8) && (bufor[13]== 0)){
				if (bufor[23]==1) {
					upakuj_eth_ip_icmp (&bufor, &pakiet_icmp, sizeof(struct eth_ip_icmp));

					printf("DATAGRAM ETH/IP/ICMP\n\n");

					printf("\nNAGLOWEK ETHERNET\n\n"); //naglowek ETHERNET
					printf("Docelowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_icmp.nagl_eth.docelowy_mac[0], pakiet_icmp.nagl_eth.docelowy_mac[1], pakiet_icmp.nagl_eth.docelowy_mac[2], pakiet_icmp.nagl_eth.docelowy_mac[3], pakiet_icmp.nagl_eth.docelowy_mac[4], pakiet_icmp.nagl_eth.docelowy_mac[5]);
					printf("Zrodlowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_icmp.nagl_eth.zrodlowy_mac[0], pakiet_icmp.nagl_eth.zrodlowy_mac[1], pakiet_icmp.nagl_eth.zrodlowy_mac[2], pakiet_icmp.nagl_eth.zrodlowy_mac[3], pakiet_icmp.nagl_eth.zrodlowy_mac[4], pakiet_icmp.nagl_eth.zrodlowy_mac[5]);
					printf("Typ protokołu:\t%x\n", pakiet_icmp.nagl_eth.typ_protokolu);

					printf("\nNAGLOWEK IP\n\n"); //naglowek IP
					printf("Wersja: %02x\n",pakiet_icmp.nagl_ip.wersja);
					printf("Dlugosc naglowka: %02x\n",pakiet_icmp.nagl_ip.dlugosc_nagl);
					printf("Typ uslugi: %x\n",pakiet_icmp.nagl_ip.typ_uslugi);
					printf("Calkowita dlugosc: %x\n",pakiet_icmp.nagl_ip.calk_dlugosc);
					printf("ID: %x\n",pakiet_icmp.nagl_ip.id);
					printf("Flaga %x\n",pakiet_icmp.nagl_ip.flaga);
					printf("Przesuniecie: 0x%x\n",pakiet_icmp.nagl_ip.przesuniecie);
					printf("Czas zycia: %02x\n",pakiet_icmp.nagl_ip.czas_zycia);
					printf("Protokol: %02x\n",pakiet_icmp.nagl_ip.protokol);
					printf("Suma kontrolna: 0x%x\n",pakiet_icmp.nagl_ip.suma_kontrolna);
					printf("Zrodlowy IP: %d.%d.%d.%d\n",pakiet_icmp.nagl_ip.zrodlowy_ip[0], pakiet_icmp.nagl_ip.zrodlowy_ip[1], pakiet_icmp.nagl_ip.zrodlowy_ip[2], pakiet_icmp.nagl_ip.zrodlowy_ip[3]);
					printf("Docelowy IP: %d.%d.%d.%d\n",pakiet_icmp.nagl_ip.docelowy_ip[0], pakiet_icmp.nagl_ip.docelowy_ip[1], pakiet_icmp.nagl_ip.docelowy_ip[2], pakiet_icmp.nagl_ip.docelowy_ip[3]);

					printf("\nNAGLOWEK ICMP\n\n"); //naglowek ICMP
					printf("Typ: %02x\n", pakiet_icmp.nagl_icmp.typ);
					printf("Kod: %02x\n", pakiet_icmp.nagl_icmp.kod);
					printf("Suma kontrolna: 0x%x\n", pakiet_icmp.nagl_icmp.suma_kontrolna);
					printf("ID: %x\n", pakiet_icmp.nagl_icmp.id);
					printf("Numer sekwencji %x\n\n", pakiet_icmp.nagl_icmp.numer_sekwencji);
					dodaj_do_listy_IP_ICMP(pakiet_icmp);

}

				if (bufor[23]==11){
					upakuj_eth_ip_udp (&bufor, &pakiet_udp, sizeof(struct eth_ip_udp));

					printf("DATAGRAM ETH/IP/UDP\n\n");

					printf("\nNAGLOWEK ETHERNET\n\n"); //naglowek ETHERNET
					printf("Docelowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_udp.nagl_eth.docelowy_mac[0], pakiet_udp.nagl_eth.docelowy_mac[1], pakiet_udp.nagl_eth.docelowy_mac[2], pakiet_udp.nagl_eth.docelowy_mac[3], pakiet_udp.nagl_eth.docelowy_mac[4], pakiet_udp.nagl_eth.docelowy_mac[5]);
					printf("Zrodlowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_udp.nagl_eth.zrodlowy_mac[0], pakiet_udp.nagl_eth.zrodlowy_mac[1], pakiet_udp.nagl_eth.zrodlowy_mac[2], pakiet_udp.nagl_eth.zrodlowy_mac[3], pakiet_udp.nagl_eth.zrodlowy_mac[4], pakiet_udp.nagl_eth.zrodlowy_mac[5]);
					printf("Typ protokołu:\t%x\n", pakiet_udp.nagl_eth.typ_protokolu);

					printf("\nNAGLOWEK IP\n\n"); //naglowek IP
					printf("Wersja: %02x\n",pakiet_udp.nagl_ip.wersja);
					printf("Dlugosc naglowka: %02x\n",pakiet_udp.nagl_ip.dlugosc_nagl);
					printf("Typ uslugi: %x\n",pakiet_udp.nagl_ip.typ_uslugi);
					printf("Calkowita dlugosc: %x\n",pakiet_udp.nagl_ip.calk_dlugosc);
					printf("ID: %x\n",pakiet_udp.nagl_ip.id);
					printf("Flaga %x\n",pakiet_udp.nagl_ip.flaga);
					printf("Przesuniecie: 0x%x\n",pakiet_udp.nagl_ip.przesuniecie);
					printf("Czas zycia: %02x\n",pakiet_udp.nagl_ip.czas_zycia);
					printf("Protokol: %02x\n",pakiet_udp.nagl_ip.protokol);
					printf("Suma kontrolna: 0x%x\n",pakiet_udp.nagl_ip.suma_kontrolna);
					printf("Zrodlowy IP: %d.%d.%d.%d\n",pakiet_udp.nagl_ip.zrodlowy_ip[0], pakiet_udp.nagl_ip.zrodlowy_ip[1], pakiet_udp.nagl_ip.zrodlowy_ip[2], pakiet_udp.nagl_ip.zrodlowy_ip[3]);
					printf("Docelowy IP: %d.%d.%d.%d\n",pakiet_udp.nagl_ip.docelowy_ip[0], pakiet_udp.nagl_ip.docelowy_ip[1], pakiet_udp.nagl_ip.docelowy_ip[2], pakiet_udp.nagl_ip.docelowy_ip[3]);

					printf("\nNAGLOWEK UDP\n\n"); //naglowek UDP
					printf("Zrodlowy port: %x\n",pakiet_udp.nagl_udp.zrodlowy_port);
					printf("Docelowy port: %x\n",pakiet_udp.nagl_udp.docelowy_port);
					printf("Dlugosc: %x",pakiet_udp.nagl_udp.dlugosc);
					printf("Suma kontrolna: 0x%x\n\n",pakiet_udp.nagl_udp.suma_kontrolna);
					dodaj_do_listy_IP_UDP(pakiet_udp);


}

				if (bufor[23]==6){
					upakuj_eth_ip_tcp (&bufor, &pakiet_tcp, sizeof(struct eth_ip_tcp));

					printf("DATAGRAM ETH/IP/TCP\n\n");

					printf("\nNAGLOWEK ETHERNET\n\n"); //naglowek ETHERNET
					printf("Docelowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_tcp.nagl_eth.docelowy_mac[0], pakiet_tcp.nagl_eth.docelowy_mac[1], pakiet_tcp.nagl_eth.docelowy_mac[2], pakiet_tcp.nagl_eth.docelowy_mac[3], pakiet_tcp.nagl_eth.docelowy_mac[4], pakiet_tcp.nagl_eth.docelowy_mac[5]);
					printf("Zrodlowy MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n", pakiet_tcp.nagl_eth.zrodlowy_mac[0], pakiet_tcp.nagl_eth.zrodlowy_mac[1], pakiet_tcp.nagl_eth.zrodlowy_mac[2], pakiet_tcp.nagl_eth.zrodlowy_mac[3], pakiet_tcp.nagl_eth.zrodlowy_mac[4], pakiet_tcp.nagl_eth.zrodlowy_mac[5]);
					printf("Typ protokołu:\t%x\n", pakiet_tcp.nagl_eth.typ_protokolu);

					printf("\nNAGLOWEK IP\n\n"); //naglowek IP
					printf("Wersja: %02x\n",pakiet_tcp.nagl_ip.wersja);
					printf("Dlugosc naglowka: %02x\n",pakiet_tcp.nagl_ip.dlugosc_nagl);
					printf("Typ uslugi: %x\n",pakiet_tcp.nagl_ip.typ_uslugi);
					printf("Calkowita dlugosc: %x\n",pakiet_tcp.nagl_ip.calk_dlugosc);
					printf("ID: %x\n",pakiet_tcp.nagl_ip.id);
					printf("Flaga %x\n",pakiet_tcp.nagl_ip.flaga);
					printf("Przesuniecie: 0x%x\n",pakiet_tcp.nagl_ip.przesuniecie);
					printf("Czas zycia: %02x\n",pakiet_tcp.nagl_ip.czas_zycia);
					printf("Protokol: %02x\n",pakiet_tcp.nagl_ip.protokol);
					printf("Suma kontrolna: 0x%x\n",pakiet_tcp.nagl_ip.suma_kontrolna);
					printf("Zrodlowy IP: %d.%d.%d.%d\n",pakiet_tcp.nagl_ip.zrodlowy_ip[0], pakiet_tcp.nagl_ip.zrodlowy_ip[1], pakiet_tcp.nagl_ip.zrodlowy_ip[2], pakiet_tcp.nagl_ip.zrodlowy_ip[3]);
					printf("Docelowy IP: %d.%d.%d.%d\n",pakiet_tcp.nagl_ip.docelowy_ip[0], pakiet_tcp.nagl_ip.docelowy_ip[1], pakiet_tcp.nagl_ip.docelowy_ip[2], pakiet_tcp.nagl_ip.docelowy_ip[3]);

					printf("\nNAGLOWEK TCP\n\n"); //naglowek TCP
					printf("Zrodlowy port: %d\n",pakiet_tcp.nagl_tcp.zrodlowy_port);
					printf("Docelowy port: %d\n",pakiet_tcp.nagl_tcp.docelowy_port);
					printf("Numer sekwencji: %02x %02x %02x %02x\n",pakiet_tcp.nagl_tcp.numer_sekwenc[0], pakiet_tcp.nagl_tcp.numer_sekwenc[1], pakiet_tcp.nagl_tcp.numer_sekwenc[2], pakiet_tcp.nagl_tcp.numer_sekwenc[3]);
					printf("Numer potwierdzenia: %02x %02x %02x %02x\n",pakiet_tcp.nagl_tcp.numer_potw[0], pakiet_tcp.nagl_tcp.numer_potw[1], pakiet_tcp.nagl_tcp.numer_potw[2], pakiet_tcp.nagl_tcp.numer_potw[3]);
					printf("Len: %d\nres: %d\nURG: %d\nACK: %d\nPSH: %d\nRST: %d\nSYN: %d\nFIN: %d\n",pakiet_tcp.nagl_tcp.len, pakiet_tcp.nagl_tcp.res, pakiet_tcp.nagl_tcp.URG, pakiet_tcp.nagl_tcp.ACK, pakiet_tcp.nagl_tcp.PSH, pakiet_tcp.nagl_tcp.RST, pakiet_tcp.nagl_tcp.SYN, pakiet_tcp.nagl_tcp.FIN);
					printf("Szerokosc okna: %x\n",pakiet_tcp.nagl_tcp.szerokosc_okna);
					printf("Suma kontrolna: 0x%x\n",pakiet_tcp.nagl_tcp.suma_kontrolna);
					printf("Wskaznik priorytetu: %x\n",pakiet_tcp.nagl_tcp.wskaznik_priorytetu);
					printf("Opcje: %x%x\n\n",pakiet_tcp.nagl_tcp.opcje[0], pakiet_tcp.nagl_tcp.opcje[1]);
					dodaj_do_listy_IP_TCP(pakiet_tcp);

				}
			}


		}}
	printf("Wysylanie pakietow\n\n");
	wyslij_ARP();
	wyslij_IP_ICMP();
	wyslij_IP_UDP();
	wyslij_IP_TCP();
	printf("Wyslano pomyslnie! \n");

		return EXIT_SUCCESS;
		}

