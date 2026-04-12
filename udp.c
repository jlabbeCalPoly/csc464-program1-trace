#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "printers.h"

const int DNS_PORT_NUMBER = 53; // Port 53 is DNS: https://en.wikipedia.org/wiki/Domain_Name_System

void formatPort(char *field, uint16_t portHost) {
    if (portHost == DNS_PORT_NUMBER) {
        formatAndPrintString(field, "DNS");
    } else {
        formatAndPrintInt(field, portHost);
    }
}

void printPort(char *field, const uint8_t *pktStart) {
    uint16_t portNet;
    memcpy(&portNet, pktStart, 2);
    uint16_t portHost = ntohs(portNet);
    formatPort(field, portHost);
}

/**
 * @brief Print the contents of the UDP header
 * 
 * @param pktData Pointer to the beginning of the UDP header
 */
void udp(const uint8_t *pktData) {
    formatAndPrintPacketHeader("UDP");

    printPort("Source Port", pktData);
    printPort("Dest Port", pktData + 2);
}
