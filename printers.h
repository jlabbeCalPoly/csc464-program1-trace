/* 
    Printers declaration 
*/

#ifndef PRINTERS_H
#define PRINTERS_H

 #include <stdint.h>

void formatAndPrintPacketHeader(char *headerType);
void formatAndPrintInt(char *field, int value);
void formatAndPrintString(char *field, char *value);
void formatAndPrintChecksum(uint16_t checksum, uint16_t checksumResult);
void formatAndPrintMacAddress(char * field, const uint8_t *pktStart);
void formatAndPrintIPAddress(char * field, const uint8_t *pktStart);

#endif