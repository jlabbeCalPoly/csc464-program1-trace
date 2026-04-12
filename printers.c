#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/**
 * @brief Formats a label and integer and prints the results to stdout
 * 
 * @param field The label/name of the field being printed
 * @param value The integer value to print
 */
void formatAndPrintInt(char *field, int value) {
    fprintf(stdout, "\t\t%s: %d\n", field, value);
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
 * @param checksum The integer value within the checksum field, in big-endian format
 * @param checksumResult The integer value of the calculated checksum, in big-endian format
 */
void formatAndPrintChecksum(uint16_t checksum, uint16_t checksumResult) {
    if (checksumResult == 0x0000) {
        formatChecksumString("Correct", checksum);
    } else {  
        formatChecksumString("Incorrect", checksum + checksumResult);
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