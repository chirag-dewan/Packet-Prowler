/**
 * @file utils.c
 * @brief Utility functions for PacketProwler.
 *
 * Contains helper functions for parsing and displaying packet information.
 */

#include "headers.h"

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
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;

    printf("\n========== Packet Details ==========\n");
    printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    printf("Protocol: %d\n", iph->protocol);
    printf("Packet Size: %d bytes\n", size);
    printf("=====================================\n");
}

