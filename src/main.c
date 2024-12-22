/**
 * @file main.c
 * @brief Entry point for the PacketProwler application.
 *
 * Ensures the program runs with root privileges and starts the packet sniffer.
 */

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
int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "PacketProwler must be run as root.\n");
        return 1;
    }

    printf("Starting PacketProwler...\n");
    if (!start_sniffer()) {
        fprintf(stderr, "Failed to start the packet sniffer.\n");
        return 1;
    }

    return 0;
}

