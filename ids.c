#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, char **argv) {

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    char lines[300][5][2048] = { "0", "0", "0", "0", "0" };
    char line[8192];

    if(argc != 3) {
        printf("usage: %s <.pcap> <.txt> \n", argv[0]);
        return -1;
    }

    FILE *f = fopen(argv[2], "r");

    while(fgets(line, sizeof(line) / sizeof(line[0]), f) != NULL)
    {

        if (strchr(line, '\n') == NULL) {
            printf("Line too long...");
            return EXIT_FAILURE;
        }

        char *ptr1 = strtok(line, " ");
        strcpy(lines[i][0], ptr1);
        char *ptr2 = strtok(NULL, " ");
        strcpy(lines[i][1], ptr2);
        char *ptr3 = strtok(NULL, " ");
        strcpy(lines[i][2], ptr3);
        char *ptr4 = strtok(NULL, " ");
        strcpy(lines[i][3], ptr4);
        char *ptr5 = strtok(NULL, "\"");
        strcpy(lines[i][4], ptr5);
        i++;
    }
    
    fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL) {
	    fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
	    return 0;
    }


    if (pcap_loop(fp, 0, packetHandler, (u_char*)&lines) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }

    return 0;

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    char (*lines)[5][2048] = (void*) userData;
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    int k = 0;
    int i;
    char *sourcePort_toString = malloc (6);
    char *destPort_toString = malloc (6);

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {

        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

            while(*lines[k][0]){

                if(strcmp(lines[k][0], sourceIP) == 0){

                    if(strcmp(lines[k][2], destIP) == 0){

                        if (ipHeader->ip_p == IPPROTO_TCP) {

                            tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                            sourcePort = (u_int) ntohs(tcpHeader->source);
                            sprintf(sourcePort_toString, "%u", sourcePort);

                            if(strcmp(lines[k][1], sourcePort_toString) == 0){

                                destPort = (u_int) ntohs(tcpHeader->dest);
                                sprintf(destPort_toString, "%u", destPort);

                                if(strcmp(lines[k][3], destPort_toString) == 0){

                                    printf("ALERT: %s\n", lines[k][4]);
                                }
                            }

                        } else if (ipHeader->ip_p == IPPROTO_UDP) {

                            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                            sourcePort = (u_int) ntohs(udpHeader->source);
                            sprintf(sourcePort_toString, "%u", sourcePort);
                            
                            if(strcmp(lines[k][1], sourcePort_toString) == 0){
                                
                                destPort = (u_int) ntohs(udpHeader->dest);
                                sprintf(destPort_toString, "%u", destPort);

                                if(strcmp(lines[k][3], destPort_toString) == 0){

                                    printf("ALERT: %s\n", lines[k][4]);
                                }
                            }
                        } 
                        // else if (ipHeader->ip_p == IPPROTO_ICMP) {
                            
                        // }
                    }
                }

                k++;
            }
    }
}