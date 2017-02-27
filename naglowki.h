#ifndef NAGLOWKI_H_
#define NAGLOWKI_H_


struct nag_eth{
	unsigned char			docelowy_mac[6];
	unsigned char			zrodlowy_mac[6];
	unsigned short  		typ_protokolu;
};


struct nag_udp{
	unsigned short 			zrodlowy_port;
	unsigned short 			docelowy_port;
	unsigned short 			dlugosc;
	unsigned short 			suma_kontrolna;
};


struct nag_icmp{
	unsigned char 			typ;
	unsigned char 			kod;
	unsigned short			suma_kontrolna;
	unsigned short			id;
	unsigned short			numer_sekwencji;
};


struct nag_ip {

	unsigned char 			wersja:4,
							dlugosc_nagl:4;

	unsigned char 			typ_uslugi;
	unsigned short 			calk_dlugosc;
	unsigned short 			id;

	unsigned short 			przesuniecie:13,
	    					flaga:3;

	unsigned char  			czas_zycia;
	unsigned char  			protokol;
	unsigned short 			suma_kontrolna;
	unsigned char   		zrodlowy_ip[4];
	unsigned char   		docelowy_ip[4];
};


struct nag_arp{
	unsigned short 			Htype;
	unsigned short 			Ptype;
	unsigned char  			dlugosc_mac;
	unsigned char  			dlugosc_ip;
	unsigned short 			opcode;
	unsigned char 			zrodlowyMAC[6];
	unsigned char 			zrodlowyIP[4];
	unsigned char 			docelowyMAC[6];
	unsigned char 			docelowyIP[4];
};


struct nag_tcp {
    unsigned short 				zrodlowy_port;
    unsigned short 				docelowy_port;
    unsigned char   			numer_sekwenc[4];
    unsigned char  				numer_potw[4];

    unsigned short 				len:4,
								res:6,
								URG:1,
								ACK:1,
								PSH:1,
								RST:1,
								SYN:1,
								FIN:1;

    unsigned short 				szerokosc_okna;
    unsigned short 				suma_kontrolna;
    unsigned short 				wskaznik_priorytetu;
    unsigned short				opcje[2];
};

//ETH LEN = 1514
struct eth_arp{
	struct nag_eth nagl_eth;
	struct nag_arp nagl_arp;
	unsigned char  bufor_danych [1472];//bo eth=14B ARP=28B
};


struct eth_ip_icmp{
	struct nag_eth nagl_eth;
	struct nag_ip nagl_ip;
	struct nag_icmp nagl_icmp;
	unsigned char bufor_danych [1474]; //ETH=14B IP=14B ICMP=8B
};


struct eth_ip_udp{
	struct nag_eth nagl_eth;
	struct nag_ip nagl_ip;
	struct nag_udp nagl_udp;
	unsigned char bufor_danych [1468]; //EH=14B IP=14B UDP=8B
};


struct eth_ip_tcp{
	struct nag_eth nagl_eth;
	struct nag_ip nagl_ip;
	struct nag_tcp nagl_tcp;
	unsigned char bufor_danych [1456]; //ETH=14B IP=14B TCP=16B
};

#endif /* NAGLOWKI_H_ */
