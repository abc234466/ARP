#include "arp.h"

#include <netinet/in.h> //warning: implicit declaration of function ‘htons’
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h> //close(int fd)
#include <arpa/inet.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_hrd = htons(type);	
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_pro = htons(type);
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->arp_op = htons(code);
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_sha, address, ETH_ALEN);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_spa, address, 4);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tha, address, ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tpa, address, 4);
}

char* get_target_protocol_addr(struct ether_arp *packet, char *info)
{
	// if you use malloc, remember to free it.
	unsigned char arptpa[4];
	
	bzero(arptpa, sizeof(arptpa));
	bzero(info, sizeof(info));
	
	memcpy(arptpa, packet->arp_tpa, 4);
	sprintf(info, "%d.%d.%d.%d", arptpa[0], arptpa[1], arptpa[2], arptpa[3]);
	return info;
}
char* get_sender_protocol_addr(struct ether_arp *packet, char *info)
{
	// if you use malloc, remember to free it.
	unsigned char arpspa[4];
	
	bzero(arpspa, sizeof(arpspa));
	bzero(info, sizeof(info));
	
	memcpy(arpspa, packet->arp_spa, 4);
	sprintf(info, "%d.%d.%d.%d", arpspa[0], arpspa[1], arpspa[2], arpspa[3]);
	return info;
}
char* get_sender_hardware_addr(struct ether_arp *packet, char *info)
{
	// if you use malloc, remember to free it.
	unsigned char arpsha[6];
	
	bzero(arpsha, sizeof(arpsha));
	bzero(info, sizeof(info));
	
	memcpy(arpsha, packet->arp_sha, 6);
	sprintf(info,"%02x:%02x:%02x:%02x:%02x:%02x", arpsha[0], arpsha[1], arpsha[2], arpsha[3], arpsha[4], arpsha[5]); 
	
	return info;
}
char* get_target_hardware_addr(struct ether_arp *packet, char *info)
{
	// if you use malloc, remember to free it.
	unsigned char arptha[6];
	
	bzero(arptha, sizeof(arptha));
	bzero(info, sizeof(info));
	
	memcpy(arptha, packet->arp_tha, 6);
	sprintf(info,"%02x:%02x:%02x:%02x:%02x:%02x", arptha[0], arptha[1], arptha[2], arptha[3], arptha[4], arptha[5]); 
	return info;
}

//get interface IP address
char* get_inf_ip(char* info, char *device)
{
	int fd;
	struct ifreq ifr;
	struct in_addr ip;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	bzero(info, sizeof(info));
	
	ifr.ifr_addr.sa_family=AF_INET;
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name)-1);

	//printf("%s\n",ifr.ifr_name);
	ioctl(fd, SIOCGIFADDR, &ifr);

	/* display result */
	//sprintf(info, "%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	memcpy(info,&ip,4);
	close(fd);
	return info;
}
//get interface MAC 
char* get_inf_mac(char* info, char *device)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	bzero(info, sizeof(info));
 
	ifr.ifr_addr.sa_family=AF_INET;
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name)-1);

	//printf("%s\n",ifr.ifr_name);
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	/* display result */
	memcpy(info,&ifr.ifr_hwaddr.sa_data,ETH_ALEN);
	/*sprintf(info,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
         (unsigned char)ifr.ifr_hwaddr.sa_data[0],
         (unsigned char)ifr.ifr_hwaddr.sa_data[1],
         (unsigned char)ifr.ifr_hwaddr.sa_data[2],
         (unsigned char)ifr.ifr_hwaddr.sa_data[3],
         (unsigned char)ifr.ifr_hwaddr.sa_data[4],
         (unsigned char)ifr.ifr_hwaddr.sa_data[5]);*/
	
	close(fd);
	return info;
}
int getInterfaceByName(int fd,char *name)
{
	int sockfd;
	struct ifreq freq;
	
	strcpy(freq.ifr_name, name);
	sockfd = ioctl(fd, SIOCGIFINDEX, &freq);
	
	return freq.ifr_ifindex;
}
