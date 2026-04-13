#include <stdint.h>
#include "printers.h"

/**
 * @brief Print the contents of the UDP header
 * 
 * @param pktData Pointer to the beginning of the UDP header
 */
void udp(const uint8_t *pktData) {
    formatAndPrintPacketHeader("UDP");

    formatAndPrintPort("Source Port", pktData);
    formatAndPrintPort("Dest Port", pktData + 2);
}
