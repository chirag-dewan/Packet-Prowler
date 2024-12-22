/**
 * @file utils.c
 * @brief Utility functions for PacketProwler.
 *
 * Contains helper functions for parsing and displaying packet information.
 */
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

static int total_packets = 0;
static int total_bytes = 0;

void print_statistics() {
    printf("\n=== Statistics ===\n");
    printf("Total Packets: %d\n", total_packets);
    printf("Total Bytes: %d\n", total_bytes);
    printf("==================\n");
}

void print_packet_info(const unsigned char *buffer, int size, const char *output_file) {
    struct ip *iph = (struct ip *)buffer;
    struct sockaddr_in source, dest;

    source.sin_addr = iph->ip_src;
    dest.sin_addr = iph->ip_dst;

    char details[256];
    snprintf(details, sizeof(details),
             "========== Packet Details ==========\n"
             "Source IP: %s\n"
             "Destination IP: %s\n"
             "Protocol: %d\n"
             "Packet Size: %d bytes\n"
             "=====================================\n",
             inet_ntoa(source.sin_addr),
             inet_ntoa(dest.sin_addr),
             iph->ip_p,
             size);

    printf("%s\n", details);

    FILE *output_file_ptr = fopen(output_file, "a");
    if (output_file_ptr) {
        fprintf(output_file_ptr, "%s\n", details);
        fclose(output_file_ptr);
    }
}

