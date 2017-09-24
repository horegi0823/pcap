#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

void printIP(struct pcap_pkthdr* header, const u_char* packet){
	struct ip *iph;
	iph=(struct ip*)(packet+sizeof(struct ether_header));
        printf("<IP information>\n");
        printf("header length : %d\n",iph->ip_hl);
        printf("version : %d\n",iph->ip_v);
        printf("type of service : %u\n",iph->ip_tos);
        printf("total packet length : %u\n",iph->ip_len);
        printf("identification : %u\n",iph->ip_id);
        printf("fragment offset : 0x%x\n",ntohs(iph->ip_off));
        printf("time to live : %u\n",iph->ip_ttl);
        printf("protocol : %u\n",iph->ip_p);
        printf("checksum : %u\n",iph->ip_sum);
        printf("soucre ip address : %s\n",inet_ntoa(iph->ip_src));
        printf("destinatio ip address : %s\n",inet_ntoa(iph->ip_dst));
}

void printTCP(struct pcap_pkthdr* header, const u_char* packet){
	struct tcphdr *tcph;
	tcph=(struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
	printf("<TCP information>\n");
	printf("source port : %u\n",ntohs(tcph->source));
	printf("destination port : %u\n",ntohs(tcph->dest));
}


int main(int argc, char* argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev=pcap_lookupdev(errbuf);
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
  		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
  		return -1;
	}

	while (true) {
  		struct pcap_pkthdr* header;//packet 정보에 대한 구조체
  		const u_char* packet;//packet 실제 데이터
  		int res = pcap_next_ex(handle, &header, &packet);
  		if (res == 0) continue;
  		if (res == -1 || res == -2) break;
  		printf("%u bytes captured\n", header->caplen);

		struct ip *iph;
		struct tcphdr *tcph;
		struct ether_header *etherneth;		

		etherneth=(struct ether_header*)packet;
		uint16_t ether_type=ntohs(etherneth->ether_type);
		printf("destination mac address :%02x:%02x:%02x:%02x:%02x:%02x\n",etherneth->ether_dhost[0],etherneth->ether_dhost[1],etherneth->ether_dhost[2],etherneth->ether_dhost[3],etherneth->ether_dhost[4],etherneth->ether_dhost[5]);
		printf("soucre mac address :%02x:%02x:%02x:%02x:%02x:%02x\n",etherneth->ether_shost[0],etherneth->ether_shost[1],etherneth->ether_shost[2],etherneth->ether_shost[3],etherneth->ether_shost[4],etherneth->ether_shost[5]);
		printf("ether_type : 0x%x\n",ether_type);
		
		if(ether_type==ETHERTYPE_IP){//ip protocol
			printIP(header,packet);
			iph=(struct ip*)(packet+sizeof(struct ether_header));
			if(iph->ip_p==IPPROTO_TCP){
				printTCP(header,packet);
			}
			int count=16;
			printf("Actual Data(16byte) : ");
			while((header->len)--){
				printf("%02x",*(packet++));
				count--;
				if(count==0){
					printf("\n");
					break;
				}
			}
		}
		printf("==========================================\n");
	}

	pcap_close(handle);
	return 0;
}
