/* 
    Printers declaration 
*/

#ifndef PRINTERS_H
#define PRINTERS_H

 #include <stdint.h>

void formatAndPrintPacketHeader(char *headerType);
void formatAndPrintInt(char *field, uint32_t value);
void formatAndPrintString(char *field, char *value);
void formatAndPrintChecksum(const uint8_t *pktData, uint8_t pktChecksumOffset, uint32_t length);
void formatAndPrintMacAddress(char * field, const uint8_t *pktStart);
void formatAndPrintIPAddress(char * field, const uint8_t *pktStart);
void formatAndPrintPort(char *field, const uint8_t *pktStart);

#endif