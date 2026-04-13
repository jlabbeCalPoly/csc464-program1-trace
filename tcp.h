#ifndef TCP_H
#define TCP_H

#include <stdint.h>

void tcp(const uint8_t *pktData, uint16_t segmentLength, uint32_t senderIPAddress, uint32_t destIPAddress, u_int8_t protocol);

#endif
