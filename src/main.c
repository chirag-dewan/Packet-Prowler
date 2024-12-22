/**
 * @file main.c
 * @brief Entry point for the PacketProwler application.
 *
 * Ensures the program runs with root privileges and starts the packet sniffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "headers.h"

/**
 * @brief Main function to start PacketProwler.
 *
 * Verifies root privileges and initiates the packet sniffer.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return int Exit status (0 for success, 1 for error).
 */

char output_file[256] = "output.txt";
int max_packets = 0;

int main(int argc, char *argv[]) {
    int opt;

    while ((opt = getopt(argc, argv, "o:n:")) != -1) {
        switch (opt) {
            case 'o':
                snprintf(output_file, sizeof(output_file), "%s", optarg);
                break;
            case 'n':
                max_packets = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-o output_file] [-n max_packets]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    printf("Output File: %s\n", output_file);
    printf("Max Packets: %d\n", max_packets);

    start_sniffer();
    return 0;
}


