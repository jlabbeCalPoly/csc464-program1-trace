// Imports
#include <pcap/pcap.h>
#include "ethernet.h"
#include "checksum.h"
#include "printers.h"

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