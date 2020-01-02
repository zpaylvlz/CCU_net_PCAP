#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <netinet/in.h>

void packet_handler(u_char *arg, const struct pcap_pkthdr *header, const u_char *content){


    struct tm *local_time;
    char timestr[100];
    time_t local_tv_sec;
    char prot[4] = "IP";
    local_tv_sec = header->ts.tv_sec;
    local_time = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", local_time);
    

    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;
    const struct udphdr *udpHeader;
    char sourceIp[INET_ADDRSTRLEN], destIp[INET_ADDRSTRLEN];

    u_int sourcePort, destPort;

    ethernetHeader = (struct ether_header *)content;

    printf("------ Packet ------\n");

    printf("Time: %s\n",timestr);
    printf("Source MAC: %s\n",ether_ntoa((const struct ether_addr *)&ethernetHeader->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((const struct ether_addr *)&ethernetHeader->ether_dhost));

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *)(content + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
	printf("Source IP: %s\n"
	"Destination IP: %s\n",sourceIp,destIp);



        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr *)(content + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->th_sport);
            destPort = ntohs(tcpHeader->th_dport);
	    strncpy(prot, "TCP", 4);
	    printf("Source Port: %d\n"
	    "Destination Port: %d\n"
	    "Protocol: %s\n",sourcePort,destPort,prot);
        }
	else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (struct udphdr *)(content + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(udpHeader->uh_sport);
            destPort = ntohs(udpHeader->uh_dport);
	    strncpy(prot, "UDP", 4);
	    printf("Source Port: %d\n"
	    "Destination Port: %d\n"
	    "Protocol: %s\n",sourcePort,destPort,prot);
        }
        else return;
    }
    else return;

   /* printf("------ Packet ------\n"
    "Time: %s\n"
    "Length: %d bytes\n"
    "Captured length: %d bytes\n"
    "Protocol: %s\n"
    "Source IP: %s\n"
    "Source Port: %d\n"
    "Destination IP: %s\n"
    "Destination Port: %d\n"
    "\n",
    timestr, header->len, header->caplen, prot,sourceIp, sourcePort, destIp, destPort);*/
}

int main(int argc, char *argv[]) {
    if(argc < 2 || argc > 3) {
        printf("Error input");
        exit(EXIT_FAILURE);
    }
    

    char *filename = argv[1];
    char *bpf_syntax = "";
    if(argc == 3) bpf_syntax = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "Cannot load %s\n" , errbuf);
        exit(EXIT_FAILURE);
    }

    struct bpf_program fp;
    if(pcap_compile(handle, &fp, bpf_syntax, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Cannot compile BPF: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Cannot apply filter %s: %s\n", bpf_syntax, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    if(pcap_loop(handle, -1, packet_handler, NULL) == -1){
        fprintf(stderr, "pcap_loop(): %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(1);
    }

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
