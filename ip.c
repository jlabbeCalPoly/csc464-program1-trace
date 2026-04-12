#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "udp.h"
#include "printers.h"
#include "checksum.h"

const int ICMP_NUMBER = 0x01;
const int TCP_NUMBER = 0x06;
const int UDP_NUMBER = 0x11;

void parseNextFromIP(const uint8_t *pktData, u_int8_t protocol, u_int8_t headerLenInBytes) {
    const uint8_t *pktNextData = pktData + headerLenInBytes;
    if (protocol == ICMP_NUMBER) {
        
    } else if (protocol == TCP_NUMBER) {
        
    } else if (protocol == UDP_NUMBER) {
        udp(pktNextData);
    }
}

void printChecksum(const uint8_t *pktData, u_int8_t headerLenInBytes) {
    uint16_t checksum;
    memcpy(&checksum, pktData + 10, 2);
    uint16_t checksumResult = in_cksum((unsigned short *)pktData, headerLenInBytes);
    uint16_t checksumHost = ntohs(checksum);
    uint16_t checksumResultHost = ntohs(checksumResult);
    formatAndPrintChecksum(checksumHost, checksumResultHost);
}

// Format the ip protocal into its representative string
char *formatIPProtocol(u_int8_t protocol) {
    if (protocol == ICMP_NUMBER) {
        return "ICMP";
    } else if (protocol == TCP_NUMBER) {
        return "TCP";
    } else if (protocol == UDP_NUMBER) {
        return "UDP";
    } else {
        return "Unknown";
    }
}

void printProtocol(uint8_t protocol) {
    char *protocolString = formatIPProtocol(protocol);
    formatAndPrintString("Protocol", protocolString);
}
 
void printTimeToLive(const uint8_t *pktStart) {
    uint8_t timeToLive;
    memcpy(&timeToLive, pktStart, 1);
    formatAndPrintInt("TTL", timeToLive);
}

void printHeaderLenInBytes(u_int8_t headerLenInBytes) {
    formatAndPrintInt("Header Len (bytes)", headerLenInBytes);
}

void printIPPDULength(const uint8_t *pktStart) {
    uint16_t totalLengthNet;
    memcpy(&totalLengthNet, pktStart, 2);
    uint16_t totalLengthHost = ntohs(totalLengthNet);
    formatAndPrintInt("IP PDU Len", totalLengthHost);
}

/**
 * @brief Print the contents of the IP header
 * 
 * @param pktData Pointer to the beginning of the IP header
 */
void ip(const uint8_t *pktData) {
    formatAndPrintPacketHeader("IP");

    uint8_t headerLenInWords = pktData[0] & 0x0F;
    // Need bytes, so multiply the number of words by 4 (1 word = 32 bits = 4 bytes))
    uint8_t headerLenInBytes = headerLenInWords * 4;

    // Save the protocol value (so inner PDUs can be parsed)
    uint8_t protocol;
    memcpy(&protocol, pktData + 9, 1);

    printIPPDULength(pktData + 2);
    printHeaderLenInBytes(headerLenInBytes);
    printTimeToLive(pktData + 8);
    printProtocol(protocol);
    printChecksum(pktData, headerLenInBytes);
    formatAndPrintIPAddress("Sender IP", pktData + 12);
    formatAndPrintIPAddress("Dest IP", pktData + 16);

    parseNextFromIP(pktData, protocol, headerLenInBytes);
}
