# pcap-programming
a program that prints the following value of packets sent and received using pcap 
[ref1](https://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro#AEN103)
[ref2](http://www.tcpdump.org/pcap.html)
- `eth.smac`, `eth.dmac`
- `ip.sip`, `ip.dip`
- `tcp.sport`, `tcp.dport`
- `data`

### OS
```
Ubuntu 16.04.2
```

### Language
```
C
```

### Compile & Execute
```
gcc -o pcap pcap.c -lpcap
```
```
sudo ./pcap -1 "port 80"
```

### Result
```
DEV : ens33
NET : 255.255.255.0
MASK : 255.255.255.0
========================================================
** IP Packet **
Src Mac : 00:0c:29:53:b3:dd
Dst Mac : 00:50:56:fd:10:1c
Src Address : 192.168.242.180
Dst Address : 119.207.66.24
** TCP Packet **
Src Port : 33500
Dst Port : 80
4500003c1cf940004006b07ec0a8f2b4
77cf421882dc00503d80f5e300000000
a00272106d730000020405b40402080a
00c4e91b000000000103030798000000
677a6b59583d751c3c00
========================================================
```
