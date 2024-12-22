/**
 * @file packet_sniffer.c
 * @brief Core functionality for capturing and analyzing network packets.
 *
 * Implements packet sniffing using libpcap, applies filters, and processes
 * captured packets to extract and log relevant information.
 */

#include "headers.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 65536

char filter_exp[256] = "tcp"; // Default filter expression

/**
 * @brief Apply a filter to the packet capture handle.
 *
 * @param handle The pcap handle to apply the filter to.
 */
void apply_filter(pcap_t *handle) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return;
    }
    printf("Filter applied: %s\n", filter_exp);
}

/**
 * @brief Starts the packet sniffer.
 *
 * Opens a network interface, applies filters, and captures packets.
 *
 * @param output_file The name of the file to write packet details to.
 * @return int Returns 1 on success, 0 on failure.
 */
int start_sniffer(const char *output_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const unsigned char *packet;

    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 0;
    }

    char *device = alldevs->name;
    printf("Using device: %s\n", device);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 0;
    }

    apply_filter(handle);

    printf("Listening for packets...\n");

    while ((packet = pcap_next(handle, &header)) != NULL) {
        print_packet_info(packet, header.len, output_file); // Pass output_file here
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 1;
}

