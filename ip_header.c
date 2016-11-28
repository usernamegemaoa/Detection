#include "ip_header.h"

void hexdump(const u_char *pkt_content, u_int length)// , u_char length)
{
	//length = 16;
	//char *result;
	const u_char *data = (u_char *)pkt_content;
	//u_char length = strlen(data);
	u_char text[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	u_int i = 0;
	u_char j;
	for (i = 0; i < length; i++) {
		if (i % 16 == 0) printf("%08d  ", i / 16);
		printf("%02X ", data[i]);
		text[i % 16] = (data[i] >= 0x20 && data[i] <= 0x7E) ? data[i] : '.';
		if ((i + 1) % 8 == 0 || i + 1 == length) printf(" ");
		if (i + 1 == length && (i + 1) % 16 != 0) {
			text[(i + 1) % 16] = '\0';
			for (j = (i + 1) % 16; j < 16; j++) printf("   ");
			if ((i + 1) % 16 <= 8) printf(" ");
		}
		if ((i + 1) % 16 == 0 || i + 1 == length) printf("|%s|\n", text);
	}

}
void packet_handle_tcp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content, u_int header_length, u_int caplen)
{
	tcp_header *tcp_protocol;
	u_int hlen;
	tcp_protocol = (tcp_header *)(pkt_content + 14 + header_length);
	hlen = tcp_protocol->offset * 4;
	printf("++++++++++++++++++++++TCP Protocol+++++++++++++++++++++++\n");

	printf("Source Port: %i\n", ntohs(tcp_protocol->src_port));
	printf("Destination Port: %i\n", ntohs(tcp_protocol->dst_port));
	printf("Sequence number: %d\n", ntohl(tcp_protocol->sequence));
	printf("Acknowledgment number: %d\n", ntohl(tcp_protocol->ack));
	printf("header Length: %d\n", tcp_protocol->offset * 4);
	printf("Flags: 0x%.3x", tcp_protocol->flags);
	if (tcp_protocol->flags & 0x08) printf("(PSH)");
	if (tcp_protocol->flags & 0x10) printf("(ACK)");
	if (tcp_protocol->flags & 0x02) printf("(SYN)");
	if (tcp_protocol->flags & 0x20) printf("(URG)");
	if (tcp_protocol->flags & 0x01) printf("(FIN)");
	if (tcp_protocol->flags & 0x04) printf("(RST)");
	printf("\n");
	printf("Windows Size: %i\n", ntohs(tcp_protocol->windows_size));
	printf("Checksum: 0x%.4\n", ntohs(tcp_protocol->checksum));
	printf("Urgent Pointer: %i\n", ntohs(tcp_protocol->urgent_pointer));
	u_char *content = (u_char *)(pkt_content + 14 + header_length + hlen);
	caplen = caplen - 14 - header_length - hlen;
	hexdump(content, caplen);
	contest_handle();


}
//udp
void packet_handle_udp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content,
	u_int header_length,
	u_int caplen)
{
	udp_header *udp_protocol;
	u_short dst_port;
	u_short src_port;
	u_short len;
	printf("++++++++++++++++++++++UDPProtocol+++++++++++++++++++++++\n");
	udp_protocol = (udp_header *)(pkt_content + 14 + header_length);
	dst_port = ntohs(udp_protocol->dst_port);
	src_port = ntohs(udp_protocol->src_port);
	len = ntohs(udp_protocol->length);

	u_char *content = (u_char *)(pkt_content + 14 + header_length + 20);
	caplen = caplen - 14 - header_length - 20;
	hexdump(content, caplen);
}
//icmp
void packet_handle_icmp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content,
	u_int header_length, u_int caplen)
{
	icmp_header *icmp_protocol;
	u_short type;
	u_short len;
	u_int ori_time;
	u_int tra_time;
	u_int rec_time;

	icmp_protocol = (icmp_header *)(pkt_content + 14 + header_length);
	printf("++++++++++++++++++++++ICMP Protocol+++++++++++++++++++++++\n");
	len = sizeof(icmp_protocol);
	type = icmp_protocol->type;
	ori_time = icmp_protocol->ori_time;
	rec_time = icmp_protocol->rec_time;
	tra_time = icmp_protocol->tra_time;

	u_char *content = (u_char *)(pkt_content + 14 + header_length + 20);
	caplen = caplen - 14 - 20 - header_length;
	hexdump(content, caplen);
}
//arp
void packet_handle_arp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content)
{
	arp_headr *arp_protocol;
	u_short protocol_type;
	u_short hardware_type;
	u_short operation_code;
	u_char hardware_length;
	u_char protocol_length;

	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = pkt_header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

	printf("++++++++++++++++++++++ARP Protocol+++++++++++++++++++++++\n");
	arp_protocol = (arp_headr *)(pkt_content + 14);
	hardware_type = ntohs(arp_protocol->hardware_type);
	protocol_type = ntohs(arp_protocol->protocol_type);
	operation_code = ntohs(arp_protocol->operation_code);
	hardware_length = arp_protocol->hardware_length;
	protocol_length = arp_protocol->protocol_length;
	switch (operation_code)
	{
	case 1:
		printf("ARP请求协议\n");
		break;
	case 2:
		printf("ARP应答协议\n");
		break;
	case 3:
		printf("RARP请求协议\n");
		break;
	case 4:
		printf("RARP应答协议\n");
		break;
	default:
		break;
	}

}
//ip
void packet_handle_ip(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content, u_int caplen)
{
	ip_header *ip_protocol;
	u_int header_length;
	u_char tos;
	u_short checksum;
	ip_address src;
	ip_address dst;
	u_char ttl;
	u_short tlen;
	u_short identification;
	u_short offset;

	printf("+++++++++++++++++++++++++++++++++++++IP Protocol+++++++++++++++++++++++++++\n");

	//SOCKADDR_IN source, dest;
	//char src_ip[MAX_ADDR_LEN], dst_ip[MAX_ADDR_LEN];

	ip_protocol = (ip_header *)(pkt_content + 14);
	//source.sin_addr.S_un.S_addr = inet_addr(ip_protocol->src);
	//dest.sin_addr.s_addr = ip_protocol->dst;
	header_length = ip_protocol->header_length * 4;
	checksum = ntohs(ip_protocol->checksum);
	tos = ip_protocol->tos;
	offset = ip_protocol->offset;
	ttl = ip_protocol->ttl;
	src = ip_protocol->src;
	dst = ip_protocol->dst;
	identification = ip_protocol->identification;
	tlen = ip_protocol->tlen;
	offset = ip_protocol->offset;

	printf("Total Length:%d\n", tlen);
	printf("Source Address -> Destination Address.\n");
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
		src.byte1,
		src.byte2,
		src.byte3,
		src.byte4,
		dst.byte1,
		dst.byte2,
		dst.byte3,
		dst.byte4);
	//printf("%d%d%c%d%d%d", src, dst, ttl, identification, tlen, offset);
	switch (ip_protocol->proto)
	{
	case 6:
		packet_handle_tcp(arg, pkt_header, pkt_content, header_length, caplen);
		break;
	case 17:
		packet_handle_udp(arg, pkt_header, pkt_content, header_length, caplen);
		break;
	case 1:
		packet_handle_icmp(arg, pkt_header, pkt_content, header_length, caplen);
		break;
	default:
		printf("Other Protocol in transfer layer!\n");
		break;
	}


}
//Ethernet
void packet_handle_eht(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content, u_int caplen)
{
	ether_header *ethernet_protocol;
	u_short ethernet_type;
	u_char *mac;

	ethernet_protocol = (ether_header *)pkt_content;
	ethernet_type = ntohs(ethernet_protocol->ehter_type);

	printf("++++++++++++++++++++++Ethernet Protocol+++++++++++++++++++++++++\n");

	mac = ethernet_protocol->ether_src;

	printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac,
		*(mac + 1),
		*(mac + 1),
		*(mac + 2),
		*(mac + 3),
		*(mac + 4),
		*(mac + 5));
	mac = ethernet_protocol->ether_dst;

	printf("Destination Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac,
		*(mac + 1),
		*(mac + 1),
		*(mac + 2),
		*(mac + 3),
		*(mac + 4),
		*(mac + 5));
	printf("Ethernet type: ");
	switch (ethernet_type)
	{
	case 0x0800:
		printf("%s\n", "IP");
		break;
	case 0x0806:
		printf("%s\n", "ARP");
		break;
	case 0x0835:
		printf("%s\n", "RARP");
		break;
	default:
		printf("%s\n", "Unknown Protocol!");
		break;
	}
	switch (ethernet_type)
	{
	case 0x0800:
		packet_handle_ip(arg, pkt_header, pkt_content, caplen);
		break;
	case 0x0806:
		packet_handle_arp(arg, pkt_header, pkt_content);
		break;
	case 0x0835:
		printf("++++++++++++++RARP Protocol++++++++++++++++++++++++\n");
		printf("RARP\n");
		break;
	default:
		printf("+++++++++++++++++Unknown Protocol++++++++++++++++++++\n");
		printf("Unknown Protocol\n");
		break;
	}
}

void contest_handle()
{

}
void wave_transform(u_char *arry, int length)
{

}