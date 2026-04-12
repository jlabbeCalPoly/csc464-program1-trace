#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "ip.h"
#include "arp.h"
#include "printers.h"

const int IP_NUMBER = 0x0800;
const int ARP_NUMBER = 0x0806;

void parseNextFromEthernet(const uint8_t *pktData, uint16_t typeShortHost) {
    const uint8_t *pktNextData = pktData + 14;
    if (typeShortHost == IP_NUMBER) {
        ip(pktNextData);
    } else if (typeShortHost == ARP_NUMBER) {
        arp(pktNextData);
    }
}

// Format the protocol type into a string based on the given type (represented as a short)
char *typeShortToString(uint16_t typeShortHost) {
    if (typeShortHost == IP_NUMBER) {
        return "IP";
    } else if (typeShortHost == ARP_NUMBER) {
        return "ARP";
    } else {
        return "Unknown";
    }
}

void printType(uint16_t typeShortHost) {
    char *typeString = typeShortToString(typeShortHost);
    formatAndPrintString("Type", typeString);
}

/**
 * @brief Print the contents of the Ethernet header
 * 
 * @param pktData Pointer to the beginning of the Ethernet header
 */
void ethernet(const uint8_t *pktData) {
    formatAndPrintPacketHeader("Ethernet");

    // determine the type, save the value in big-endian (so inner PDUs can be parsed)
    uint16_t typeShortNet;
    memcpy(&typeShortNet, pktData + 12, 2);
    uint16_t typeShortHost = ntohs(typeShortNet);

    formatAndPrintMacAddress("Dest MAC", pktData);
    formatAndPrintMacAddress("Source MAC", pktData + 6);
    printType(typeShortHost);

    parseNextFromEthernet(pktData, typeShortHost);
}
