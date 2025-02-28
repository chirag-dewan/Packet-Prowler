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
 #include <time.h>
 #include <signal.h>
 
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
  * @param max_packets Maximum number of packets to capture (0 for unlimited).
  * @return int Returns 1 on success, 0 on failure.
  */
 int start_sniffer(const char *output_file, int max_packets);
 
 /**
  * @brief Prints information about a captured packet.
  *
  * Parses the IP header of the captured packet and prints the source and destination
  * IP addresses, protocol type, and packet size.
  *
  * @param buffer The buffer containing the captured packet data.
  * @param size The size of the captured packet.
  * @param output_file The file to write packet details to.
  * @param max_packets Maximum number of packets to capture.
  * @return int Returns 1 if max packets reached, 0 otherwise.
  */
 int print_packet_info(const unsigned char *buffer, int size, const char *output_file, int max_packets);
 
 /**
  * @brief Print capture statistics
  */
 void print_statistics();
 
 /**
  * @brief Initialize the signal handlers
  */
 void init_signal_handlers();
 
 /**
  * @brief Convert protocol number to name
  * 
  * @param protocol_num The protocol number from IP header
  * @return const char* The protocol name
  */
 const char* get_protocol_name(int protocol_num);
 
 #endif // HEADERS_H