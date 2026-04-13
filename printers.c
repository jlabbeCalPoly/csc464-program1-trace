#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "checksum.h"

/**
 * @brief Formats the header print statement
 * 
 * @param headerType The specific type (IP, ARP, ...) of the header
 */
void formatAndPrintPacketHeader(char *headerType) {
    fprintf(stdout, "\n\t%s Header\n", headerType);
}

/**
 * @brief Formats a label and integer and prints the results to stdout
 * 
 * @param field The label/name of the field being printed
 * @param value The integer value to print
 */
void formatAndPrintInt(char *field, uint32_t value) {
    fprintf(stdout, "\t\t%s: %u\n", field, value);
}

/**
 * @brief Formats a label and string and prints the results to stdout
 * 
 * @param field The label/name of the field being printed
 * @param value The string value to print
 */
void formatAndPrintString(char *field, char *value) {
    fprintf(stdout, "\t\t%s: %s\n", field, value);
}

/**
 * Formats a comparison result (Correct/Incorrect) and hex value of the checksum, printing to stdout
 * 
 * comparisonResult "Correct" or "Incorrect"
 * checksumResult The value of the checksum, displayed in hex
 */
void formatChecksumString(char *comparisonResult, uint16_t checksumResult) {
    /*
        Need to make sure to covert to big-endian since there are multiple bytes,
        as well as specify the amount of expected chars for the hexidecimal representation
    */
    fprintf(stdout, "\t\tChecksum: %s (0x%04x)\n", comparisonResult, checksumResult);
}

/**
 * @brief Compares the provided checksum and calculated checksum to determine if a bit-flip occurred
 * 
 * @param pktData The address of the header
 * @param pktChecksumOffset Where the checksum information is located, relative to the header start
 * @param headerLenInBytes The length of the header, in bytes
 */
void formatAndPrintChecksum(const uint8_t *pktData, uint8_t pktChecksumOffset, uint32_t length) {
    uint16_t checksum;
    memcpy(&checksum, pktData + pktChecksumOffset, 2);
    uint16_t checksumResultHost = in_cksum((unsigned short *)pktData, length);
    uint16_t checksumHost = ntohs(checksum);

    if (checksumResultHost == 0x0000) {
        formatChecksumString("Correct", checksumHost);
    } else {  
        formatChecksumString("Incorrect", checksumHost);
    }
}

/**
 * @brief Format 6 bytes into a printable representation of the MAC address
 * 
 * @param field The label/name of the field being printed
 * @param pktStart The address to begin copying bytes from
 */
void formatAndPrintMacAddress(char * field, const uint8_t *pktStart) {
    char buffer[6];
    memcpy(buffer, pktStart, 6);
    formatAndPrintString(field, ether_ntoa((const struct ether_addr *)buffer));
}

/**
 * @brief Format 4 bytes into a printable representation of the MAC address
 * 
 * @param field The label/name of the field being printed
 * @param pktStart The address to begin copying bytes from
 */
void formatAndPrintIPAddress(char * field, const uint8_t *pktStart) {
    uint32_t ipAddress;
    memcpy(&ipAddress, pktStart, 4);

    struct in_addr addr;
    addr.s_addr = ipAddress;
    formatAndPrintString(field, inet_ntoa(addr));
}

void formatPort(char *field, uint16_t portHost) {
    // Ports found here: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
    const int DNS_PORT_NUMBER = 53;
    const int HTTP_PORT_NUMBER = 80;

    if (portHost == DNS_PORT_NUMBER) {
        fprintf(stdout, "\t\t%s:  %s\n", field, "DNS");
    } else if (portHost == HTTP_PORT_NUMBER) {
        fprintf(stdout, "\t\t%s:  %s\n", field, "HTTP");
    } else {
        fprintf(stdout, "\t\t%s:  %u\n", field, portHost);
    }
}

/**
 * @brief Format and print ports
 * 
 * @param field The label/name of the field being printed
 * @param pktStart The address to begin copying bytes from
 */
void formatAndPrintPort(char *field, const uint8_t *pktStart) {
    uint16_t portNet;
    memcpy(&portNet, pktStart, 2);
    uint16_t portHost = ntohs(portNet);
    formatPort(field, portHost);
}