// Imports
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <string.h>
#include <arpa/inet.h>
#include "checksum.h"

void formatAndPrintInt(char *field, int value) {
    printf("\t\t%s: %d\n", field, value);
}

void formatAndPrintString(char *field, char *value) {
    printf("\t\t%s: %s\n", field, value);
}

void formatChecksumString(char *comparisonResult, u_int16_t checksumResult) {
    /*
        Need to make sure to covert to big-endian since there are multiple bytes,
        as well as specify the amount of expected chars for the hexidecimal representation
    */
    printf("\t\tChecksum: %s (0x%04x)\n", comparisonResult, ntohs(checksumResult));
}

void formatAndPrintChecksum(u_int16_t checksum, u_int16_t checksumResult) {
    if (checksumResult == 0x0000) {
        formatChecksumString("Correct", checksum);
    } else {  
        formatChecksumString("Incorrect", checksum + checksumResult);
    }
}

// Format the protocol type into a string based on the given type (represented as a short)
char *formatPType(u_int16_t pTypeShortHost) {
    if (pTypeShortHost == 0x0800) {
        return "IP";
    } else {
        return "Unknown";
    }
}

// Format the ip protocal into its representative string
char *formatProtocol(u_int8_t protocol) {
    if (protocol == 0x01) {
        return "ICMP";
    } else if (protocol == 0x06) {
        return "TCP";
    } else if (protocol == 0x11) {
        return "UDP";
    } else {
        return "Unknown";
    }
}

void ip(const u_int8_t *pktData) {
    printf("\n\tIP Header\n");

    u_int8_t headerLenInWords = pktData[0] & 0x0F;
    // Need bytes, so multiply the number of words by 4 (1 word = 32 bits = 4 bytes))
    u_int8_t headerLenInBytes = headerLenInWords * 4;

    u_int16_t totalLengthNet;
    memcpy(&totalLengthNet, pktData + 2, 2);

    u_int8_t timeToLive;
    memcpy(&timeToLive, pktData + 8, 1);

    u_int8_t protocol;
    memcpy(&protocol, pktData + 9, 1);
    char *protocolString = formatProtocol(protocol);

    u_int16_t checksum;
    memcpy(&checksum, pktData + 10, 2);
    u_int16_t checksumResult = in_cksum((unsigned short *)pktData, headerLenInBytes);

    // Print the IP PDU length
    formatAndPrintInt("IP PDU Len", ntohs(totalLengthNet));

    // Print the header len in bytes
    formatAndPrintInt("Header Len (bytes)", headerLenInBytes);

    // Print the header len (in bytes, so multiply the number of words by 4 (1 word = 32 bits = 4 bytes))
    formatAndPrintInt("TTL", timeToLive);

    // Print the IP protocol
    formatAndPrintString("Protocol", protocolString);

    // Print the Checksum results
    formatAndPrintChecksum(checksum, checksumResult);
}

void ethernet(const u_int8_t *pktData) {
    printf("\n\tEthernet Header\n");
    char srcBuffer[6];
    char destBuffer[6];
    memcpy(srcBuffer, pktData, 6);
    memcpy(destBuffer, pktData + 6, 6);

    u_int16_t pTypeShortNet;
    memcpy(&pTypeShortNet, pktData + 12, 2);
    
    // Converts from little-endian to big-endian
    u_int16_t pTypeShortHost = ntohs(pTypeShortNet);
    char *typeString = formatPType(pTypeShortHost);

    // Print the destination MAC address
    formatAndPrintString("Dest MAC", ether_ntoa((const struct ether_addr *)srcBuffer));

    // Print the source MAC address
    formatAndPrintString("Source MAC", ether_ntoa((const struct ether_addr *)destBuffer));

    // Print the type
    formatAndPrintString("Type", typeString);

    if (pTypeShortHost == 0x0800) {
        const u_int8_t *pktNextData = pktData + 14;
        ip(pktNextData);
    }
}

int main(int argc, char *argv[]) {
    /*
        The expected parameters for this program are:
            1) Program name (trace)
            2) The pcap file that's being analyzed
    */
    char errBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcapStruct = pcap_open_offline(argv[1], errBuffer);

    if (pcapStruct == NULL) {
        fprintf(stderr, "Error: %s", errBuffer);
        return 1;
    } else {
        struct pcap_pkthdr *pktHeader;
        const u_int8_t *pktData;
        int pktNum = 0;
        /*
            Continue reading packets while the pcap file has unprocessed ones
            pcap_next_ex returns:
            1 on success (there's a packet that can be processed)
            PCAP_ERROR_BREAK (there's no more packets to read)
            PCAP_ERROR (there was an issue that occurred while reading the packet)
        */
        while (pcap_next_ex(pcapStruct, &pktHeader, &pktData) == 1) {
            pktNum += 1;
            printf("\nPacket number: %d  Packet Len: %d\n", pktNum, pktHeader->len);

            ethernet(pktData);
        }

        pcap_close(pcapStruct);
        return 0;
    }
}