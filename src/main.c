#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "headers.h"

// Global variables
char output_file[256] = "output.txt";
int max_packets = 0;

/**
 * @brief Print usage instructions
 * 
 * @param program_name The name of the executable
 */
void print_usage(const char *program_name) {
    printf("PacketProwler - A Lightweight Network Packet Sniffer\n\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -o FILE   Specify output file (default: output.txt)\n");
    printf("  -n NUM    Capture only NUM packets (default: unlimited)\n");
    printf("  -f FILTER Set capture filter (default: tcp or udp or icmp)\n");
    printf("  -h        Display this help and exit\n\n");
    printf("Examples:\n");
    printf("  %s -o capture.log -n 100    # Capture 100 packets to capture.log\n", program_name);
    printf("  %s -f \"udp port 53\"         # Capture only DNS traffic\n\n", program_name);
    printf("Note: This program requires root/administrator privileges.\n");
}

int main(int argc, char *argv[]) {
    int opt;
    extern char filter_exp[256]; // Defined in packet_sniffer.c

    while ((opt = getopt(argc, argv, "o:n:f:h")) != -1) {
        switch (opt) {
            case 'o':
                snprintf(output_file, sizeof(output_file), "%s", optarg);
                break;
            case 'n':
                max_packets = atoi(optarg);
                if (max_packets <= 0) {
                    fprintf(stderr, "Warning: Invalid packet count. Using unlimited.\n");
                    max_packets = 0;
                }
                break;
            case 'f':
                snprintf(filter_exp, sizeof(filter_exp), "%s", optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Print configuration
    printf("\nPacketProwler Configuration:\n");
    printf("----------------------------\n");
    printf("Output File: %s\n", output_file);
    if (max_packets > 0) {
        printf("Max Packets: %d\n", max_packets);
    } else {
        printf("Max Packets: Unlimited\n");
    }
    printf("Filter: %s\n", filter_exp);
    printf("----------------------------\n\n");

    // Check if running as root/administrator
    if (getuid() != 0) {
        fprintf(stderr, "Error: This program requires root/administrator privileges.\n");
        fprintf(stderr, "Please run with sudo or as root.\n");
        return EXIT_FAILURE;
    }

    // Start the packet sniffer, passing both output_file and max_packets
    if (!start_sniffer(output_file, max_packets)) {
        fprintf(stderr, "Error: Failed to start packet sniffer.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}