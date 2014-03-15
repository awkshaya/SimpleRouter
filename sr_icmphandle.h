#ifndef SR_ICMPHANDLE_H 
#define SR_ICMPHANDLE_H

#include <sys/types.h>

#include "sr_router.h"

#define ICMP_HDR_LEN 8 
void handle_icmppacket(struct sr_instance* sr, uint32_t src_ipaddr, uint32_t dest_ipaddr, uint8_t* packet, int length, int icmptype);



#endif /* SR_ICMPHANDLE_H */
