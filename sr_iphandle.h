#ifndef SR_IPHANDLE_H 
#define SR_IPHANDLE_H

#include <sys/types.h>
#include "sr_router.h"

#define IPV4_HDR_LEN 20
#define PACKET_TTL 64
void send_ippacket(struct sr_instance* sr, uint32_t src_ipaddr, uint32_t dest_ipaddr, uint8_t* buffer, int length, unsigned char type, int through);
void handle_ippacket(struct sr_instance* sr, uint8_t* buffer, int length,char* recvinterface);


#endif /* SR_IP_H */
