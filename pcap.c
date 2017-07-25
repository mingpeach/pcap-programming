// Developer: ming
// platform: Ubuntu 16.04.2
// lib : libpcap
// Reference : http://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro

#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

struct ethernet *eth; // Ethernet header structure
struct ip *iph; // IP header structure
struct tcphdr *tcph; // TCP header structure

void process_data(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct ether_header *eh;
	uint16_t ether_type;
	int chcnt = 0;
	int length;
	char buf[20];

	const u_char *ip_packet;
	const u_char *data;

	// Get Ethernet header
	eh = (struct ether_header *)packet;

	// Add offset to get IP header
	ip_packet = packet + sizeof(struct ether_header);	

	// Get protocol type
	ether_type = ntohs(eh->ether_type);
	
	// IP packet
	if(ether_type == ETHERTYPE_IP) {
		iph = (struct ip *)ip_packet;

		printf("** IP Packet **\n");
		
		// print ethernet source mac & dest mac
		printf("Src Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eh->ether_shost[0], eh->ether_shost[1], 
			eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
		printf("Dst Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", eh->ether_dhost[0], eh->ether_dhost[1], 
			eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);

		// print IP source ip & dest ip
		printf("Src Address : %s\n", inet_ntop(AF_INET, &(iph->ip_src), buf, sizeof(buf)));
        	printf("Dst Address : %s\n", inet_ntop(AF_INET, &(iph->ip_dst), buf, sizeof(buf)));
		
		// TCP packet
		if(iph->ip_p == IPPROTO_TCP) {
			tcph = (struct tcphdr *)(ip_packet + iph->ip_hl * 4);
			data = ip_packet + (tcph->th_off * 4);
	
			printf("** TCP Packet **\n");

			// print TCP source port & dest port
            		printf("Src Port : %d\n" , ntohs(tcph->th_sport));
           		printf("Dst Port : %d\n" , ntohs(tcph->th_dport));

			// get data length
			length = iph->ip_len - (iph->ip_hl * 4) - (tcph->th_off * 4);
			
			//while(length--) {
			//	printf("%02x", *(data++)); 
            		//	if ((++chcnt % 16) == 0) printf("\n");
        		//}

		}

		printf("\n========================================================\n");
	}
}

int main(int argc, char *argv[]) {

	char *dev, *net, *mask, buf[20];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	int res;

    	struct in_addr net_addr, mask_addr;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;

	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	// pcap_lookupnet()
	int ret; 
	bpf_u_int32 netp;
    	bpf_u_int32 maskp;

	// pcap_compile()
	struct bpf_program fp;     

	/*** GET DEVICE NAME ***/
	dev = pcap_lookupdev(errbuf);
	/*
	 * char *pcap_lookupdev(char *errbuf);
	 * errbuf: at least PCAP_ERRBUF_SIZE chars
	 * returns a pointer to a string giving the name of a network device suitable for use
	 * 	with pcap_create() and pcap_activate(), or with pcap_open_live(), 
	 * 	and with pcap_lookupnet().
	 * If there is an error, NULL is returned and errbuf is filled in with an appropriate
	 * 	error message.
	 */

	if (dev == NULL) {
		printf("%s\n", errbuf);
		exit(1);
	}
	printf("DEV : %s\n", dev);

	/*** GET NETWORK/MASK INFO ***/
	//ret = pcap_lookupnet("dum0", &netp, &maskp, errbuf);
	/*
	 * int pcap_lookupnet(const char *device, bpf_u_int32 *netp,
	 *	bpf_u_int32 *maskp, char *errbuf);
	 * used to determine the IPv4 network number and mask associated with the network device
	 * device: device
	 * netp, maskp: bpf_u_int32 pointers
	 * errbuf: at least PCAP_ERRBUF_SIZE chars
	 * returns 0 on success.
	 * returns -1 on failure. If -1 is returned, errbuf if filled in with an appropriate
	 * 	error message. 
	 */
	if (ret == -1) {
		printf("%s\n", errbuf);
		exit(1);
	}

	/*** PRINT NETWORK & MASK INFORMATION ***/
	net_addr.s_addr = netp;
	net = inet_ntop(AF_INET, &net_addr, buf, sizeof(buf));
	if(net == NULL) { // exception handling for no net
		perror("inet_ntop");
		exit(1);
	}
	
	mask_addr.s_addr = maskp;
	mask = inet_ntop(AF_INET, &mask_addr, buf, sizeof(buf));
	if(mask == NULL) { // exception handling for no mask
		perror("inet_ntop");
		exit(1);
	}

    	printf("NET : %s\n",net);
    	printf("MASK : %s\n", mask);
    	printf("========================================================\n");

	/*** PACKET CAPTURE ***/
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	/* 
	 * pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf);
	 * device: device
	 * snaplen: an integer which defines the maximum number of bytes to be captured by pcap
	 * promisc: when set to true, brings the interface into promiscuous mode
	 * to_ms: the read time out in milliseconds
	 * ebuf: a string we can store any error messages within
	 * returns our session handler
	 */
	
	if (handle == NULL) {
		printf("%s\n", errbuf);
		exit(1);
	}

	/*** COMPILE OPTION ***/
	if (pcap_compile(handle, &fp, NULL, 0, netp) == -1) {
		printf("compile error\n");
		exit(1);
	}
	/* 
	 * int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, 
	 *	int optimize, bpf_u_int32 netmask);
	 * used to compile the string str into a filter program
	 * fp: a pointer to a bpf_program struct and is filled in by pcap_compile()
	 * optimize: controls whether optimization on the resulting code is performed.
	 * netmask: specifies the IPv4 netmask of the network on which packets are being captured;
	 * 	it is used only when checking for IPv4 broadcast addresses in the filter program.
	 * returns 0 on success.
	 * returns -1 on failure. If -1 is returned, pcap_geterr() or pcap_perror() may be called
	 * 	with p as an argument to fetch or display the error text.
	 */

	
	/*** SET FILTER ***/
	//if (pcap_setfilter(handle, &fp) == -1) {
		//printf("setfilter error\n");
		//exit(0);
	//}
	/*
	 * int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
	 * used to specify a filter program.
	 * fp: a pointer to a bpf_program struct, usually the result of a call to pcap_compile()
	 * returns 0 on success.
	 * returns -1 on failure. If -1 is returned, pcap_geterr() or pcap_perror() may be called
	 * 	with p as an argument to fetch or display the error text.
	 */

	while(1) {
		res = pcap_next_ex(handle, &header, &pkt_data);
		/*
		 * int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
		 * 	const u_char **pkt_data);
		 * read the next packet from a pcap_t  
		 * handle: 
		 * struct pcap_pkthdr pkt_header
		 * conster
		 */
		if (res == 0||res == -1) continue;
		process_data(header, pkt_data);

		if (res == -2) {
			printf("end of file\n");
			exit(1);
		}
	}

	return(0);
}
