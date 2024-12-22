/**
 * @file utils.c
 * @brief Utility functions for PacketProwler.
 *
 * Contains helper functions for parsing and displaying packet information.
 */

#include "headers.h"
#include <netinet/ip.h> // For IP header parsing
#include <netinet/in.h> // For sockaddr_in structure

/**
 * @brief Prints information about a captured packet.
 *
 * Parses the IP header of the captured packet and prints the source and destination
 * IP addresses, protocol type, and packet size.
 *
 * @param buffer The buffer containing the captured packet data.
 * @param size The size of the captured packet.
 */
void print_packet_info(const unsigned char *buffer, int size) {
    // Cast the buffer directly to IP header
    struct ip *iph = (struct ip *)(buffer);
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    // Populate source and destination addresses
    source.sin_addr = iph->ip_src;
    dest.sin_addr = iph->ip_dst;

    printf("\n========== Packet Details ==========\n");
    printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    printf("Protocol: %d\n", iph->ip_p);
    printf("Packet Size: %d bytes\n", size);
    printf("=====================================\n");
}

