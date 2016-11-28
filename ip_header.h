#include "pcap.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "winsock2.h"
#include "time.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16

#define the Ethernet header


typedef struct ether_header{
	u_char ether_dst[6];        //destination address
	u_char ether_src[6];		//source address
	u_short ehter_type;			//ethernet type
}ether_header;

typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
//typedef struct ip_address{
//	u_char addr[4];
//}ip_address;

//ipv4
typedef struct ip_header{
#ifdef WORDS_BIGENDIAN
	u_char ip_version : 4, header_length : 4;
#else
	u_char header_length : 4, ip_version : 4;
#endif

	u_char ver_ihl;		//version and length
	u_char tos;			//quality of the service
	u_short tlen;		//total length
	u_short identification;		//
	u_short offset;		//group offset
	u_char ttl;			// time to live
	u_char proto;		//protocol
	u_short checksum;	//
	ip_address dst;		//destination address
	ip_address src;		//source address
	u_int op_pad;		//
}ip_header;

//tcp
typedef struct tcp_header{
	u_short dst_port;
	u_short src_port;
	u_int sequence;
	u_int ack;
#ifdef WORDS_BIGENDIAN
	u_char offset : 4, reserved : 4;
#else
	u_char reserved : 4, offset : 4;
#endif
	u_char flags;
	u_short windows_size;
	u_short checksum;
	u_short urgent_pointer;
}tcp_header;

//udp
typedef struct udp_header{
	u_short dst_port;
	u_short src_port;
	u_short length;
	u_short checksum;
}udp_header;

typedef struct icmp_header{
	u_char type;
	u_char code;
	u_short checksum;
	u_short identifier;
	u_short sequence;
	u_long ori_time;
	u_long rec_time;
	u_long tra_time;

}icmp_header;

typedef struct arp_header{
	u_short hardware_type;
	u_short protocol_type;
	u_char hardware_length;
	u_char protocol_length;
	u_short operation_code;
	u_char src_eth_addr[6];
	u_char src_ip_addr[4];
	u_char dst_eth_addr[6];
	u_char dst_ip_addr[4];
}arp_headr;

typedef struct pkt_arry{
	ip_address src;
	ip_address dst;
	u_char pkt_len;
	int num;
	float rate;
	const u_char *content;
}pkt_arry;

typedef struct pkt_set{
	u_char len;
	const u_char *pkt_data;
}pkt_set;

void hexdump(const u_char *pkt_content, u_int length);

void packet_handle_tcp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content, u_int header_length, u_int caplen);

void packet_handle_udp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content,
	u_int header_length,
	u_int caplen);
//icmp
void packet_handle_icmp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content,
	u_int header_length, u_int caplen);

//arp
void packet_handle_arp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content);

//ip
void packet_handle_ip(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content, u_int caplen);


//Ethernet
void packet_handle_eht(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content, u_int caplen);


void contest_handle();

void pkt_aggregat(pkt_set arry[], int length);

void calc_rate(pkt_arry arry[], int length);
void judge(pkt_arry arry[], int length);