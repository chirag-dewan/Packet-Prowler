/**
 * @file packet_sniffer.c
 * @brief Core functionality for capturing and analyzing network packets.
 *
 * Implements the main logic for packet sniffing using raw sockets. Processes
 * captured packets to extract and log relevant information.
 */

#include "headers.h"

/**
 * @brief Starts the packet sniffer.
 *
 * Creates a raw socket to capture all incoming packets on the network interface.
 * Processes each packet to extract and display its details.
 *
 * @return int Returns 1 on success, 0 on failure.
 */
int start_sniffer() {
    int sock_raw;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    // Create raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket creation failed");
        free(buffer);
        return 0;
    }

    printf("Listening for packets...\n");
    while (1) {
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (data_size < 0) {
            perror("Failed to receive packets");
            close(sock_raw);
            free(buffer);
            return 0;
        }

        print_packet_info(buffer, data_size);
    }

    close(sock_raw);
    free(buffer);
    return 1;
}

