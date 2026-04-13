#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "printers.h"

const int SYN_FLAG_MASK = 0x02; // 0x02 = 00000010
const int RST_FLAG_MASK = 0x04; // 0x03 = 00000100
const int FIN_FLAG_MASK = 0x01; // 0x03 = 00000001
const int ACK_FLAG_MASK = 0x10; // 0x03 = 00010000

void buildChecksumBuffer(uint8_t tcpChecksumBuffer[], 
    uint32_t senderIPAddress, 
    uint32_t destIPAddress,
    uint8_t protocol,
    uint16_t segmentLength,
    const uint8_t *pktData
) {
    memcpy(tcpChecksumBuffer, &senderIPAddress, 4);
    memcpy(tcpChecksumBuffer + 4, &destIPAddress, 4);
    tcpChecksumBuffer[8] = 0;
    memcpy(tcpChecksumBuffer + 9, &protocol, 1);

    uint16_t length = htons(segmentLength);
    memcpy(tcpChecksumBuffer + 10, &length, 2);
    memcpy(tcpChecksumBuffer + 12, pktData, segmentLength);
}

void printWindowSize(const uint8_t *pktStart) {
    uint16_t windowSizeNet;
    memcpy(&windowSizeNet, pktStart, 2);
    uint16_t windowSizeHost = ntohs(windowSizeNet);
    formatAndPrintInt("Window Size", windowSizeHost);
}

char *formatFlag(uint8_t flagValue) {
    if (flagValue == 0) {
        return "No";
    } else {
        return "Yes";
    }
}

void printFlag(char *field, const uint8_t *pktStart, uint8_t bitMask) {
    uint8_t flagValue = pktStart[0] & bitMask;
    char *flagString = formatFlag(flagValue);
    formatAndPrintString(field, flagString);
}

void printLongNumber(char *field, const uint8_t *pktStart) {
    uint32_t numberNet;
    memcpy(&numberNet, pktStart, 4);
    uint32_t numberHost = ntohl(numberNet);
    formatAndPrintInt(field, numberHost);
}

/**
 * @brief Print the contents of the TCP header
 * 
 * @param pktData Pointer to the beginning of the TCP header
 * @param segmentLength The length of the TCP header + payload
 * @param senderIPAddress The IP address of the sending device in the IP Header
 * @param destIPAddress The destination address of the destination device in the IP Header
 * @param protocol The protocol number (0x06)
 */
void tcp(const uint8_t *pktData, 
    uint16_t segmentLength,
    uint32_t senderIPAddress,
    uint32_t destIPAddress,
    uint8_t protocol
) {
    formatAndPrintPacketHeader("TCP");

    // bitwise and to get the value of the header length (first 4 bits)
    //uint8_t headerLenInWords = pktData[12] & 0xF0; // 0xFO = 11110000

    // Need bytes, so multiply the number of words by 4 (1 word = 32 bits = 4 bytes. 4 / 2^4 = 1 / 2^2 = 1 / 4)
    //uint8_t headerLenInBytes = headerLenInWords / 4;

    formatAndPrintInt("Segment Length", segmentLength);
    formatAndPrintPort("Source Port", pktData);
    formatAndPrintPort("Dest Port", pktData + 2);
    printLongNumber("Sequence Number", pktData + 4);
    printLongNumber("ACK Number", pktData + 8);
    printFlag("SYN Flag", pktData + 13, SYN_FLAG_MASK);
    printFlag("RST Flag", pktData + 13, RST_FLAG_MASK);
    printFlag("FIN Flag", pktData + 13, FIN_FLAG_MASK);
    printFlag("ACK Flag", pktData + 13, ACK_FLAG_MASK);
    printWindowSize(pktData + 14);
    
    uint32_t bufferLen = 12 + segmentLength;
    uint8_t tcpChecksumBuffer[bufferLen];
    buildChecksumBuffer(
        tcpChecksumBuffer,
        senderIPAddress,
        destIPAddress,
        protocol,
        segmentLength,
        pktData
    );
    formatAndPrintChecksum(tcpChecksumBuffer, 28, bufferLen);
}