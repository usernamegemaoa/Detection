#include "ip_header.h"
#include "stdio.h"
#include "stdlib.h"

#define packet_len_threshold 90
#define MAX_LENGTH 10000
//#define PACKET_LENGTH 90


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	u_int j = 0;
	pcap_t *adhandle;
	char packet_filter[] = "ip and tcp"; //过滤，只获取ipv4的tcp包
	struct bpf_program fcode;
	int res;
	u_int netmask;
	u_char packat_len;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	pkt_set arry[MAX_LENGTH];
	int current_len = 0;
	char temp;

	time_t start_time, current_time;
	int duration;
	


	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选中的适配器 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
								65536,            // 要捕捉的数据包的部分 
													// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
								PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
								1000,             // 读取超时时间
								NULL,             // 远程机器验证
								errbuf            // 错误缓冲池
								)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("Please input the time (s) you want to capture the packet:");
	scanf("%d", &duration);
	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	start_time = time(NULL);
	current_time = time(NULL);
	/* 获取数据包 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0 && current_time - start_time <duration  ){

		if (res == 0)
			/* 超时时间到 */
			continue;

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
		//hexdump(pkt_data,header->len);
		packat_len = header->caplen;
		if (packat_len <= packet_len_threshold)
		{
			//insert to the pcaket_len_set
			if (current_len  < MAX_LENGTH)
			{
				arry[current_len].pkt_data = pkt_data;
				arry[current_len].len = packat_len;
				++current_len;
			}
			else
			{
				//增加内存

				printf("memory exhausted!\n");

			}
		}
		current_time = time(NULL);
	}

	if (res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	printf("Capture %d packets.\n", current_len);
	pkt_aggregat(arry, current_len, duration);
	//free(arry);
	scanf("%s",&temp);
	return 0;
}
