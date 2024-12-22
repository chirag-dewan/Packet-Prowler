/**
 * @file packet_sniffer.c
 * @brief Core functionality for capturing and analyzing network packets on macOS.
 *
 * Uses Berkeley Packet Filter (BPF) to capture packets on macOS.
 */

#include "headers.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <stdio.h>

#define BUFFER_SIZE 65536


char filter_exp[256] = "tcp"; // Default filter expression

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
 * @brief Starts the packet sniffer on macOS.
 *
 * Opens a BPF device, attaches it to the default network interface, and captures
 * packets for processing.
 *
 * @return int Returns 1 on success, 0 on failure.
 */

int start_sniffer() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const unsigned char *packet;

    char *device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return 0;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 0;
    }

    apply_filter(handle);

    while ((packet = pcap_next(handle, &header)) != NULL) {
        print_packet_info(packet, header.len);
    }

    pcap_close(handle);
    return 1;
}

