#include "ip_header.h"
#include "stdio.h"
#include "stdlib.h"

#define packet_len_threshold 90
#define MAX_LENGTH 10000


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	u_int j = 0;
	pcap_t *adhandle;
	int res;
	u_char packat_len;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	u_char *arry = (u_char *)malloc(MAX_LENGTH * 2);
	int current_len = 0;

	time_t start_time, current_time, duration;
	printf("Please input the time (s) you want to capture the packet:");
	scanf("%d", &duration);


	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�е������� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��
								65536,            // Ҫ��׽�����ݰ��Ĳ��� 
													// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
								PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
								1000,             // ��ȡ��ʱʱ��
								NULL,             // Զ�̻�����֤
								errbuf            // ���󻺳��
								)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ����б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	start_time = time(NULL);
	current_time = time(NULL);
	/* ��ȡ���ݰ� */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0 && current_time - start_time <duration  ){

		if (res == 0)
			/* ��ʱʱ�䵽 */
			continue;

		/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
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
				arry[current_len] = packat_len;
				++current_len;
			}
			else
			{
				//�����ڴ�

				printf("memory exhausted!\n");

			}
		}
	}

	if (res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	wave_transform(arry,current_len);
	free(arry);
	return 0;
}
