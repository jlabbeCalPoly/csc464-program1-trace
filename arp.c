#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "printers.h"

const int REQUEST_NUMBER = 0x0001;
const int REPLY_NUMBER = 0x0002;

// Format the opcode into its representative string
char *formatOpcode(u_int16_t opcodeHost) {
    if (opcodeHost == REQUEST_NUMBER) {
        return "Request";
    } else if (opcodeHost == REPLY_NUMBER) {
        return "Reply";
    } else {
        return "Error";
    }
}

void printOpcode(const uint8_t *pktStart) {
    uint16_t opcodeNet;
    memcpy(&opcodeNet, pktStart, 2);
    uint16_t opcodeHost = ntohs(opcodeNet);
    char *opcodeString = formatOpcode(opcodeHost);
    formatAndPrintString("Opcode", opcodeString);
}

/**
 * @brief Print the contents of the ARP header
 * 
 * @param pktData Pointer to the beginning of the ARP header
 */
void arp(const uint8_t *pktData) {
    fprintf(stdout, "\n\tARP header\n");

    printOpcode(pktData + 6);
    formatAndPrintMacAddress("Sender MAC", pktData + 8);
    formatAndPrintIPAddress("Sender IP", pktData + 14);
    formatAndPrintMacAddress("Target MAC", pktData + 18);
    formatAndPrintIPAddress("Target IP", pktData + 24);
}
