/**
 * @file packet_sniffer.c
 * @brief Core functionality for capturing and analyzing network packets on macOS.
 *
 * Uses Berkeley Packet Filter (BPF) via libpcap to capture packets.
 */

#include "headers.h"
#include <pcap.h> // Libpcap header for packet capture

#define BUFFER_SIZE 65536

/**
 * @brief Starts the packet sniffer on macOS.
 *
 * Opens the default network interface using libpcap and captures packets.
 *
 * @return int Returns 1 on success, 0 on failure.
 */
int start_sniffer() {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer to hold error messages
    pcap_t *handle;

    // Find the default network interface
    char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error finding default device: %s\n", errbuf);
        return 0;
    }
    printf("Using device: %s\n", device);

    // Open the device for packet capture
    handle = pcap_open_live(device, BUFFER_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return 0;
    }

    printf("Listening for packets on %s...\n", device);

    // Capture packets in a loop
    struct pcap_pkthdr header;
    const unsigned char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        print_packet_info(packet, header.len);
    }

    pcap_close(handle);
    return 1;
}

