pcap.o :
	gcc -o pcap pcap.c -lpcap

clean : 
	rm *.o pcap


