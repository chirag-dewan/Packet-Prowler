/**
 * @file headers.h
 * @brief Common headers and function declarations for PacketProwler.
 *
 * This file includes necessary platform-specific networking headers
 * and declares the functions used across the project.
 */

#ifndef HEADERS_H
#define HEADERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#ifdef __APPLE__
// macOS Ethernet header
#include <net/ethernet.h>
#else
// Linux Ethernet header
#include <netinet/ether.h>
#endif

/**
 * @brief Starts the packet sniffer.
 *
 * Opens a network interface, applies filters, and captures packets.
 *
 * @param output_file The name of the file to write packet details to.
 * @return int Returns 1 on success, 0 on failure.
 */
int start_sniffer(const char *output_file);

/**
 * @brief Prints information about a captured packet.
 *
 * Parses the IP header of the captured packet and prints the source and destination
 * IP addresses, protocol type, and packet size.
 *
 * @param buffer The buffer containing the captured packet data.
 * @param size The size of the captured packet.
 * @param output_file The file to write packet details to.
 */
void print_packet_info(const unsigned char *buffer, int size, const char *output_file);

#endif // HEADERS_H

