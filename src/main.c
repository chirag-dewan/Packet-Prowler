#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "headers.h"

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

    start_sniffer(output_file); // Pass output_file
    return 0;
}

