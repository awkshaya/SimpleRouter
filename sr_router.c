/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_iphandle.h"
#include "sr_icmphandle.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("\nTime(EPOCH): %lld - Received packet of length %d:\n",(long long)time(0),len);

	
	/*  Preamble 7
		delimiter 1    (sr_handlepacket() leaves us this ptr)
		dest addr 6   (reverse order)
		src addr 6     (reverse oddr)
		type/len 2     (amount in data frame
		data 0-1500
		pad  0-46
		checksum 4      (last)
	*/	
		
	/* fill in code here */
	//cannot use "new", must use malloc since this is C  - Jiexi
	struct sr_frame frameobj; //this only exists in this scope anyway, no need for malloc
	struct sr_frame* frame = &frameobj;
	frame->sr = sr;
	//need to copy frame, so do not modify them!
	frame->packet = malloc(len);
	memcpy(frame->packet, packet, len);
	frame->len = len;
	
	int interfacelen = strlen(interface) + 1; //strlen() doesn't include '\0' byte
	frame->interface = malloc(interfacelen);
	memcpy(frame->interface, interface, interfacelen);
	
	//http://www.beej.us/guide/bgnet/output/html/multipage/htonsman.html
	//we need ntohs() network to host short for figuring out the type
	unsigned short type; // 2 bytes instead of 4.
	memcpy(&type, frame->packet + ETHER_ADDR_LEN + ETHER_ADDR_LEN, sizeof(unsigned short)); //12 bytes in
	type = ntohs(type);

	print_hdrs((uint8_t*)frame, sizeof(struct sr_frame));
	
	if(type == ethertype_ip){ //IP to IP frame
		uint8_t* content = frame->packet + ETHER_HDR_LEN;
		handle_ippacket(frame->sr, content, frame->len - ETHER_HDR_LEN,frame->interface);
		printf("handled IP packet \n");
	}
	
	
	if(type == ethertype_arp){ //ARP request
		struct sr_arp_hdr* arphdr = (struct sr_arp_hdr*)(frame->packet + ETHER_HDR_LEN);
		handle_arppacket(frame->sr, frame->interface, arphdr);
		printf("handled arp request \n");
	}
	//free the malloced space within frameobj
	free(frame->packet);
	free(frame->interface);

}/* end sr_ForwardPacket */



//find longest matching mask for ipaddr
struct sr_rt* findroute(struct sr_instance* sr, uint32_t ipaddr){
	struct sr_rt* longestmatch = NULL;
	struct sr_rt* iterator = sr->routing_table;
	
	while(iterator != NULL){ //iterate all entries in routing table
		
		//apply mask to entries we are checkign against
		uint32_t ipmasked = ipaddr & iterator->mask.s_addr;
		uint32_t matchagainst = iterator->dest.s_addr & iterator->mask.s_addr;
		if(ipmasked == matchagainst){
			if(longestmatch == NULL ||(iterator->mask.s_addr >= longestmatch->mask.s_addr))
				longestmatch = iterator;
				
		}
		iterator = iterator->next; //check next one
	}

	return longestmatch;
}

//search through our available interfaces for the one asked for by rt
struct sr_if* findinterface(struct sr_instance* sr, struct sr_rt* rt){
	if(rt == NULL) //make sure we have a route
		return NULL;
	struct sr_if* iterator = sr->if_list; //get interfaces
	while(iterator != NULL){ //check all interfaces
		if(strcmp(rt->interface,iterator->name) == 0) //A MATCH!
			return iterator;
		iterator = iterator->next; //check next
	}
	return NULL; // :( NO MATCHES!?!
}

/*
	if(rt == NULL) //make sure we have a route
		return 0;
	
	//fetch entry from cache if available
	uint8_t* packet = sr->packet;
	struct sr_arpentry* entry = sr_arpcache_lookup(packet,rt->gw.s_addr);
	if(entry == NULL)
		return 0;
	memcpy(macaddr,entry->mac,ETHER_ADDR_LEN); //copy gateway mac addr into macaddr
	free(entry);
	return 1;		
*/

//send frame to destination through available routes and return status
int sendframe(struct sr_instance* sr, uint32_t ipaddr, uint8_t* packet, unsigned int len, uint16_t type){

	printf("sending frame out \n");
	struct sr_ip_hdr* iphdr = (struct sr_ip_hdr*)packet;
	
	struct sr_rt* route = findroute(sr, ipaddr);
	if(route == NULL){ //we cannot reach this destination
		handle_icmppacket(sr, 0, iphdr->ip_src, packet, len, 3);
		return -1;
	}

	struct sr_if* interface = findinterface(sr,route);
	if(interface == NULL) //couldn't find interface by name
		return -1;

	unsigned char dest_macaddr[ETHER_ADDR_LEN];
	unsigned char src_macaddr[ETHER_ADDR_LEN];	//save our src addr 
	memcpy(src_macaddr, interface->addr, ETHER_ADDR_LEN);
	
	uint8_t* buffer = malloc(ETHER_HDR_LEN + len); //create buffer to hold header and len of packet
	

	struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache),route->gw.s_addr); //find out if we have arp cache of this addr
	if(entry != NULL){ //found arp

		memcpy(dest_macaddr,entry->mac,ETHER_ADDR_LEN); //copy gateway mac addr into macaddr
		free(entry); //sr_arpcache_lookup malloced this, so free it
		

		memcpy(buffer + ETHER_HDR_LEN,packet,len); //copy packet into buffer
		memcpy(buffer,dest_macaddr,ETHER_ADDR_LEN); //copy dest on
		memcpy(buffer + ETHER_ADDR_LEN,src_macaddr,ETHER_ADDR_LEN );
		memcpy(buffer + ETHER_ADDR_LEN + ETHER_ADDR_LEN,&type,2); //type/len field 2 bytes
		
		int result = sr_send_packet(sr,buffer,ETHER_HDR_LEN + len, interface->name);
		free(buffer); //clean up before return
		return result;	
	}
	else{ //did not find arp
		memcpy(buffer + ETHER_HDR_LEN,packet,len); //copy packet into buffer
		memcpy(buffer,dest_macaddr,ETHER_ADDR_LEN); //copy dest on
		memcpy(buffer + ETHER_ADDR_LEN,src_macaddr,ETHER_ADDR_LEN );
		memcpy(buffer + ETHER_ADDR_LEN + ETHER_ADDR_LEN,&type,2); //type/len field 2 bytes
		
		struct sr_arpreq *arpreq = sr_arpcache_queuereq(&(sr->cache),route->gw.s_addr,buffer,ETHER_HDR_LEN + len,interface->name);
		handle_arpreq(sr, arpreq);
		return -1;
	}
	
}