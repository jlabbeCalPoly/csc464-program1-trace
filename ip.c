#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "printers.h"

const int ICMP_NUMBER = 0x01;
const int TCP_NUMBER = 0x06;
const int UDP_NUMBER = 0x11;

void parseNextFromIP(
    const uint8_t *pktData, 
    uint8_t protocol, 
    uint16_t totalLengthHost, 
    uint8_t headerLenInBytes,
    uint32_t senderIPAddress,
    uint32_t destIPAddress
) {
    const uint8_t *pktNextData = pktData + headerLenInBytes;
    if (protocol == ICMP_NUMBER) {
        icmp(pktNextData);
    } else if (protocol == TCP_NUMBER) {
        tcp(pktNextData, totalLengthHost - headerLenInBytes, senderIPAddress, destIPAddress, protocol);
    } else if (protocol == UDP_NUMBER) {
        udp(pktNextData);
    }
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

void printIPPDULength(const uint16_t totalLengthHost) {
    formatAndPrintInt("IP PDU Len", totalLengthHost);
}

/**
 * @brief Print the contents of the IP header
 * 
 * @param pktData Pointer to the beginning of the IP header
 */
void ip(const uint8_t *pktData) {
    formatAndPrintPacketHeader("IP");

    uint16_t totalLengthNet;
    memcpy(&totalLengthNet, pktData + 2, 2);
    uint16_t totalLengthHost = ntohs(totalLengthNet);

    uint8_t headerLenInWords = pktData[0] & 0x0F;
    // Need bytes, so multiply the number of words by 4 (1 word = 32 bits = 4 bytes))
    uint8_t headerLenInBytes = headerLenInWords * 4;

    // Save the protocol value (so inner PDUs can be parsed)
    uint8_t protocol;
    memcpy(&protocol, pktData + 9, 1);

    printIPPDULength(totalLengthHost);
    printHeaderLenInBytes(headerLenInBytes);
    printTimeToLive(pktData + 8);
    printProtocol(protocol);
    formatAndPrintChecksum(pktData, 10, headerLenInBytes);

    uint32_t senderIPAddress;
    memcpy(&senderIPAddress, pktData + 12, 4);
    formatAndPrintIPAddress("Sender IP", pktData + 12);

    uint32_t destIPAddress;
    memcpy(&destIPAddress, pktData + 16, 4);
    formatAndPrintIPAddress("Dest IP", pktData + 16);

    parseNextFromIP(pktData, protocol, totalLengthHost, headerLenInBytes, senderIPAddress, destIPAddress);
}
