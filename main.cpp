#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct ifreq ifr;
unsigned char* mac;
unsigned char* dmac;

void usage() {
	printf("syntax: send-arp-test <interface> <sender_ip> <target_ip>\n");
	printf("sample: send-arp-test wlan0 x.x.x.x 10.14.1.1\n");
}

void getMacAddr(char *dev) {
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;	
}

int sendArp(pcap_t* handle, uint32_t sip, uint32_t tip, uint16_t type){
	EthArpPacket packet;
	packet.arp_.tip_ = htonl(Ip(tip));	
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = 6;
	packet.arp_.pln_ = 4;

	if(type == htons(ArpHdr::Request)){
		packet.eth_.dmac_= Mac("FF:FF:FF:FF:FF:FF");	


	} else if (type == htons(ArpHdr::Reply)){
		packet.eth_.dmac_ = Mac(dmac);
	}

	packet.eth_.smac_ = Mac(mac);
	packet.arp_.sip_ = Ip(sip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00");	// target mac

	if(type == htons(ArpHdr::Request)){
		packet.arp_.tmac_ = Mac("00:00:00:00:00");	// target mac
	} else if (type == htons(ArpHdr::Reply)){
		packet.arp_.tmac_ = Mac(dmac);
	}

	packet.arp_.tip_ = Ip(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}

	return 0;

}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	EthArpPacket packet;

	uint32_t sender_ip = inet_addr(argv[2]);
	uint32_t target_ip = inet_addr(argv[3]);
	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);

	getMacAddr(dev);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	sendArp(handle, sender_ip, target_ip, htons(ArpHdr::Request));

	while ( true ) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		EthHdr* eth_p = (EthHdr*) packet;
		if ( eth_p->type_ != htons(0x0806)) continue;

		ArpHdr* arp_p = (ArpHdr*) ((uint8_t*)(packet) + 14);
		if (arp_p->tmac_ == (Mac)mac) continue;

		dmac = (u_char*)arp_p->smac_;
		memcpy(dmac, &arp_p->smac_, 6);
	
		break;
	}

	while ( true ) {
		if (sendArp(handle, sender_ip, target_ip, htons(ArpHdr::Reply)) != 0) {
			return -1;
		}
	}

	pcap_close(handle);
}


// void printNetInfo(u_char* buf, u_char* buf2) {
// 	printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
// 	printf("IP: %d.%d.%d.%d", buf2[0], buf2[1], buf2[2], buf2[3]);
// }