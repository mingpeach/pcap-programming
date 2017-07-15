#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// IP header structure
struct ip *iph;

// TCP header structure
struct tcphdr *tcph;

int main(int argc, char *argv[]) {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

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
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
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
		fprintf(stderr, "Couldn't find default device %s: %s\n", dev, errbuf);
		return(2);
	}


	/*** COMPILE OPTION ***/
	if (pcap_compile(handle, &fp, argv[2], 0, netp) == -1) {
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
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("setfilter error\n");
		exit(0);
	}
	/*
	 * int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
	 * used to specify a filter program.
	 * fp: a pointer to a bpf_program struct, usually the result of a call to pcap_compile()
	 * returns 0 on success.
	 * returns -1 on failure. If -1 is returned, pcap_geterr() or pcap_perror() may be called
	 * 	with p as an argument to fetch or display the error text.
	 */
  
	return(0);
}
