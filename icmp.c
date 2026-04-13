#include <stdint.h>
#include <string.h>
#include "printers.h"

// Request/Reply numbers: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
const int ECHO_REPLY_NUMBER = 0;
const int ECHO_REQUEST_NUMBER = 8;

void formatAndPrintEchoType(uint8_t echoType) {
    if (echoType == ECHO_REPLY_NUMBER) {
        formatAndPrintString("Type", "Reply");
    } else if (echoType == ECHO_REQUEST_NUMBER) {
        formatAndPrintString("Type", "Request");
    } else {
        formatAndPrintInt("Type", echoType);
    }
}

void printEchoType(const uint8_t *pktStart) {
    uint8_t echoType;
    memcpy(&echoType, pktStart, 1);
    formatAndPrintEchoType(echoType);
}

/**
 * @brief Print the contents of the ICMP header
 * 
 * @param pktData Pointer to the beginning of the ICMP header
 */
void icmp(const uint8_t *pktData) {
    formatAndPrintPacketHeader("ICMP");

    printEchoType(pktData);
}
