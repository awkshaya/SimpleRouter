#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_icmphandle.h"
#include "sr_iphandle.h"
//helper to send our icmp packets
void send_icmppacket(struct sr_instance* sr, uint32_t src_ipaddr, uint32_t dest_ipaddr, uint8_t* rest, int length, uint8_t icmp_type,
					  uint8_t icmp_code, uint32_t icmp_rest){
	/* struct sr_icmp_hdr* icmphdr = malloc(ICMP_HDR_LEN + length);
		uint8_t* buffer = (uint8_t*)icmp_hdr;
	*/
	printf("send_icmppacket() \n");

	
	uint8_t* buffer = malloc(ICMP_HDR_LEN + length); //room for icmp header and the data accompanying it
	struct sr_icmp_hdr* icmphdr = (struct sr_icmp_hdr*) buffer; // use the space we just malloced
	icmphdr->icmp_type = icmp_type;
	icmphdr->icmp_code = icmp_code;
	icmphdr->icmp_rest = icmp_rest;
	icmphdr->icmp_sum = 0; //Jiexi - fails if not set for some reason
	memcpy(buffer + ICMP_HDR_LEN, rest, length);
	icmphdr->icmp_sum = cksum(icmphdr, ICMP_HDR_LEN + length);
	
	if(src_ipaddr != 0)
		send_ippacket(sr, src_ipaddr, dest_ipaddr, buffer, ICMP_HDR_LEN + length, ip_protocol_icmp, 1); //Justin - need to adjust declaration in ip_handle.h
	else
		send_ippacket(sr, 0, dest_ipaddr, buffer, ICMP_HDR_LEN + length, ip_protocol_icmp, 0);
		
	free(buffer);
}


void handle_icmppacket(struct sr_instance* sr, uint32_t src_ipaddr, uint32_t dest_ipaddr, uint8_t* packet, int length, int icmptype){
	/*
		icmptype
		echo 0
		host not reachable 1
		ttl timeout 2
		dest not reachable 3
		port not reachable 4
	*/
	printf("handle_icmppacket() type: %i\n",icmptype);
	
	if(icmptype == 0){ //echo
		struct sr_icmp_hdr* icmphdr = (struct sr_icmp_hdr*)(packet + IPV4_HDR_LEN);
		printf("icmp packet of type %i\n",icmphdr->icmp_type);
		//make sure this is a request
		if(icmphdr->icmp_type == 8){
			//make sure packet is not corrupt
			uint16_t origsum = icmphdr->icmp_sum;
			icmphdr->icmp_sum = 0;
			icmphdr->icmp_sum = cksum(icmphdr, length - IPV4_HDR_LEN);
			if(origsum == icmphdr->icmp_sum) //make sure the packet is not corrutp before forwarding the contents to next interface
				send_icmppacket(sr, dest_ipaddr, src_ipaddr, packet + ICMP_HDR_LEN + IPV4_HDR_LEN, length - ICMP_HDR_LEN - IPV4_HDR_LEN, 0, 0, icmphdr->icmp_rest);
		}
	}
	else{
		//setup for others
		int sendlen; //we want the biffer length
		if(length > IPV4_HDR_LEN + 8)
			sendlen = length;
		else
			sendlen = IPV4_HDR_LEN + 8;
		
		switch(icmptype){
		case 1: //host not reachable
			send_icmppacket(sr, src_ipaddr, dest_ipaddr, packet, sendlen, 3, 1, 0);
			break;
		case 2: //ttl
			send_icmppacket(sr, src_ipaddr, dest_ipaddr, packet, sendlen, 11, 0, 0);
			break;
		case 3: //dest not reachable
			send_icmppacket(sr, src_ipaddr, dest_ipaddr, packet, sendlen, 3, 0, 0);
			break;
		case 4: //port not reachable
			send_icmppacket(sr, src_ipaddr, dest_ipaddr, packet, sendlen, 3, 3, 0);
			break;
		default:
			break;
		}
	}
}


