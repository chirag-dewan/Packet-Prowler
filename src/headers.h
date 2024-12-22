/**
 * @file headers.h
 * @brief Common headers and function declarations for PacketProwler.
 *
 * This file includes platform-specific networking headers and declares the functions
 * used across the project.
 */

#ifndef HEADERS_H
#define HEADERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifdef __APPLE__
// macOS Ethernet header
#include <net/ethernet.h>
#else
// Linux Ethernet header
#include <netinet/ether.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Starts the packet sniffer.
 *
 * Initializes raw sockets and listens for incoming packets.
 *
 * @return int Returns 1 on success, 0 on failure.
 */
int start_sniffer();

/**
 * @brief Prints information about a captured packet.
 *
 * Parses the captured packet to extract details like source and destination IP addresses,
 * protocol type, and packet size.
 *
 * @param buffer The buffer containing the captured packet data.
 * @param size The size of the captured packet.
 */
void print_packet_info(const unsigned char *buffer, int size);

#endif // HEADERS_H

