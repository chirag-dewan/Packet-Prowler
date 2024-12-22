#ifndef HEADERS_H
#define HEADERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>            // For packet capture
#include <netinet/ip.h>      // For IP header structure
#include <netinet/in.h>      // For sockaddr_in

// Function declarations
int start_sniffer();
void print_packet_info(const unsigned char *buffer, int size);

#endif // HEADERS_H

