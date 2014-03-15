#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h" //contains arphandle
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_iphandle.h"
#include "sr_icmphandle.h"
//added
#include "sr_utils.h"
#include "sr_rt.h"
/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
	//printf("scanning cache for arp request updates\n");
	struct sr_arpreq* iterator = sr->cache.requests;
	while(iterator != NULL){ //while our iterator has not reached the end
		handle_arpreq(sr, iterator);
		iterator = iterator->next;
	}
}

	/*  Preamble 7
		delimiter 1   
		dest addr 6   (reverse order)
		src addr 6     (reverse oddr)
		type/len 2     (amount in data frame
		data 0-1500
		pad  0-46
		checksum 4      (last)
	*/	

//ETHER_HDR_LEN = 14 -> 6 + 6 + 2	

//handle incomming arp requests
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* request){
	printf("incomming arp request\n");
	//find out if we need to refresh
	time_t current = time(NULL); //no adjust
	double askagain = 0.8; //ask if we haven't in the last 0.8 seconds
	if((current - request->sent) > askagain){ //time to ask again
		if(request->times_sent < 5){ //hasn't responded 5 times
			uint8_t* buffer = malloc(sizeof(struct sr_arp_hdr) + ETHER_HDR_LEN);
			struct sr_arp_hdr* arphdr = (struct sr_arp_hdr*)(buffer + ETHER_HDR_LEN);
			arphdr->ar_hrd = htons(arp_hrd_ethernet);
			arphdr->ar_hln = ETHER_ADDR_LEN;
			arphdr->ar_pro = htons(ethertype_ip);
			arphdr->ar_pln = 4;
			arphdr->ar_op = htons(arp_op_request);
			arphdr->ar_tip = request->ip;
			memset(arphdr->ar_tha, 0, ETHER_ADDR_LEN);
			/*

			*/
			struct sr_rt* route = findroute(sr,request->ip);
			struct sr_if* interface = findinterface(sr, route);

			arphdr->ar_sip = interface->ip;
			
			memcpy(arphdr->ar_sha, interface->addr, ETHER_ADDR_LEN);		
			memcpy(buffer + ETHER_ADDR_LEN,interface->addr,ETHER_ADDR_LEN);
			memset(buffer, 255, ETHER_ADDR_LEN);
			uint16_t proto = htons(ethertype_arp);
			memcpy(buffer+ETHER_ADDR_LEN+ETHER_ADDR_LEN,&proto,2);
			
			
			print_hdr_arp(buffer);
			//send off the packet
			sr_send_packet(sr,buffer,sizeof(struct sr_arp_hdr) + ETHER_HDR_LEN, interface->name);
			
			request->sent = current; //update time to new
			request->times_sent = request->times_sent + 1; //increment
			free(buffer);
		}
		else{ //unreachable
			struct sr_packet* packet = request->packets; //loop through the packets associated with this request
			while(packet != NULL){
				uint8_t* frame;
				frame = (uint8_t*)(packet->buf);
				frame += ETHER_HDR_LEN;
				
				struct sr_ip_hdr* iphdr = (struct sr_ip_hdr*)frame;
				struct sr_icmp_hdr* icmphdr = (struct sr_icmp_hdr*)(frame+IPV4_HDR_LEN);
				print_hdr_icmp(frame);
				if(iphdr->ip_p != ip_protocol_icmp || icmphdr->icmp_code == 8){ //packet is valid, then send it out
					iphdr->ip_ttl = iphdr->ip_ttl + 1;
					iphdr->ip_sum = 0;
					iphdr->ip_sum = cksum(iphdr,IPV4_HDR_LEN);
					handle_icmppacket(sr, 0, iphdr->ip_src, frame, packet->len - ETHER_HDR_LEN, 1);
				}
				
				packet = packet->next; //iterate
			}
			sr_arpreq_destroy(&(sr->cache), request);
		}
	
	}
}

//handle arp packets outgoing
void handle_arppacket(struct sr_instance* sr, char* interface, struct sr_arp_hdr* arphdr){
	printf("handling outgoing arppacket\n");
	uint8_t* buffcopy = (uint8_t*)arphdr;
	print_hdr_arp(buffcopy);
	
	if(ntohs(arphdr->ar_pro) == ethertype_ip && ntohs(arphdr->ar_hrd) == arp_hrd_ethernet && 
		(ntohs(arphdr->ar_op) == arp_op_request || ntohs(arphdr->ar_op) == arp_op_reply) &&
		arphdr->ar_pln == 4){
		
		int cached = 0;
		pthread_mutex_lock(&(sr->cache.lock));
		struct sr_arpentry* arpentry = sr_arpcache_lookup(&(sr->cache), arphdr->ar_sip);
		if(arpentry != NULL){
			arpentry->valid = 1;
			cached = 1;
			memcpy(arpentry->mac, arphdr->ar_sha, ETHER_ADDR_LEN);
		}
		pthread_mutex_unlock(&(sr->cache.lock));
		
		struct sr_if* iterator = sr->if_list;
		while(iterator != NULL){
		
			if(iterator->ip != arphdr->ar_tip || strcmp(iterator->name, interface) != 0){ ///not valid interface
				iterator = iterator->next;
				continue;
			}
		
			if(cached == 0){
				//try to add into current cache
				struct sr_arpreq* arpinsert = sr_arpcache_insert(&(sr->cache),arphdr->ar_sha,arphdr->ar_sip);
				if(arpinsert != NULL){
					struct sr_packet* packet = arpinsert->packets; //loop packets
					while(packet != NULL){
						memcpy(packet->buf,arphdr->ar_sha,ETHER_ADDR_LEN);
						sr_send_packet(sr, packet->buf, packet->len, interface);
						packet = packet->next; //iterate	
					}
					sr_arpreq_destroy(&(sr->cache),arpinsert);
				}
			}
			
			if(ntohs(arphdr->ar_op) == arp_op_request){
				arphdr->ar_tip = arphdr->ar_sip;
				arphdr->ar_sip = iterator->ip;
				arphdr->ar_op = htons(arp_op_reply);
				memcpy(arphdr->ar_tha,arphdr->ar_sha,ETHER_ADDR_LEN);
				memcpy(arphdr->ar_sha,iterator->addr,ETHER_ADDR_LEN);
				
				uint8_t* buffer = malloc(sizeof(struct sr_arp_hdr) + ETHER_HDR_LEN);
				memcpy(buffer,arphdr->ar_tha,ETHER_ADDR_LEN);
				memcpy(buffer+ETHER_ADDR_LEN,arphdr->ar_sha,ETHER_ADDR_LEN);
				
				uint16_t proto = htons(ethertype_arp);
				memcpy(buffer+ETHER_ADDR_LEN+ETHER_ADDR_LEN,&proto,2);
				memcpy(buffer+ETHER_ADDR_LEN,arphdr->ar_sha,ETHER_ADDR_LEN);

				memcpy(buffer+ETHER_HDR_LEN,buffcopy,sizeof(struct sr_arp_hdr));
				
				sr_send_packet(sr,buffer,sizeof(struct sr_arp_hdr)+ETHER_HDR_LEN,iterator->name);
				
				free(buffer);
			}
			
			break;
		}
	}

}





/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

