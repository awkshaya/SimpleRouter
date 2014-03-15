#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_icmphandle.h"
#include "sr_iphandle.h"
//help icmp send out it's responses
void send_ippacket(struct sr_instance* sr, uint32_t src_ipaddr, uint32_t dest_ipaddr, uint8_t* buffer, 
					int length, unsigned char type, int through){
	printf("send_ippacket() with op: %i\n",through);
	
    struct sr_rt* rt = findroute(sr, dest_ipaddr);
	if(through == 0){
		struct sr_if* interface = findinterface(sr, rt);					
		if(interface == NULL)	//make sure we have a match in the routing table			
			return;
		src_ipaddr = interface->ip;
	}
	
	uint8_t* frame_buffer = malloc(IPV4_HDR_LEN + length);
	memset(frame_buffer,0,IPV4_HDR_LEN + length);
	struct sr_ip_hdr* iphdr = (struct sr_ip_hdr*)frame_buffer;
	
	iphdr->ip_v = 4; //version 4
	iphdr->ip_hl = 5;
	iphdr->ip_ttl = PACKET_TTL;
	iphdr->ip_len = htons(IPV4_HDR_LEN + length); //host to network
	iphdr->ip_p = type; //protocol
	iphdr->ip_src = src_ipaddr;
	iphdr->ip_dst = dest_ipaddr;
	
	memcpy(frame_buffer + IPV4_HDR_LEN, buffer, length);
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum(iphdr, IPV4_HDR_LEN);
	sendframe(sr, dest_ipaddr, frame_buffer, IPV4_HDR_LEN + length, htons(ethertype_ip));
	free(frame_buffer);				
}

//handle incomming packets
void handle_ippacket(struct sr_instance* sr, uint8_t* buffer, int length,char* recvinterface){
	printf("handle_ippacket()\n");
	struct sr_ip_hdr* iphdr = (struct sr_ip_hdr*)buffer;
	

	
	int ourip = 0;
	struct sr_if* interface = sr->if_list;
	while(interface != NULL){
		if(interface->ip == iphdr->ip_dst){
			ourip = 1;
			break;
		}
		interface = interface->next;
	}

	if(ourip != 0){
		if(iphdr->ip_p == ip_protocol_icmp){
			printf("**ping request incomming** \n");
			print_hdr_icmp(buffer);
			handle_icmppacket(sr, iphdr->ip_src, iphdr->ip_dst, buffer, length, 0);
		}
		else{ //we shouldn't be the target of an IP packet if the destination is literally the interface
			printf("**unreachable port** \n");
			print_hdr_icmp(buffer);	
			
			//get receiving interface ip again
			struct sr_if* rinterface = sr->if_list;
			while(rinterface != NULL){
				if(strcmp(rinterface->name,recvinterface) == 0){
					break;
				}
				rinterface = rinterface->next;
			}			
			
			handle_icmppacket(sr, rinterface->ip, iphdr->ip_src , buffer, length, 4);			
		}
	}
	else{
		if(iphdr->ip_ttl > 1){
			print_hdr_ip(buffer);
			iphdr->ip_ttl = iphdr->ip_ttl -1;
			iphdr->ip_sum = 0;
			uint8_t* header = (uint8_t*)iphdr;
			iphdr->ip_sum = cksum(header,IPV4_HDR_LEN);
			sendframe(sr, iphdr->ip_dst, buffer, length, htons(ethertype_ip));
		}
		else
			handle_icmppacket(sr, 0, iphdr->ip_src, buffer, length, 2);
	}
}