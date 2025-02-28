/**
 * @file utils.c
 * @brief Utility functions for PacketProwler.
 *
 * Contains helper functions for parsing and displaying packet information.
 */
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "headers.h"

// Track statistics
static int total_packets = 0;
static int total_bytes = 0;

// Define protocol numbers
#define ICMP 1
#define TCP 6
#define UDP 17

/**
 * @brief Convert protocol number to name
 * 
 * @param protocol_num The protocol number from IP header
 * @return const char* The protocol name
 */
const char* get_protocol_name(int protocol_num) {
    switch(protocol_num) {
        case ICMP:
            return "ICMP";
        case TCP:
            return "TCP";
        case UDP:
            return "UDP";
        default:
            return "Unknown";
    }
}

/**
 * @brief Print capture statistics
 */
void print_statistics() {
    printf("\n=== Statistics ===\n");
    printf("Total Packets: %d\n", total_packets);
    printf("Total Bytes: %d\n", total_bytes);
    printf("Average Packet Size: %.2f bytes\n", 
           total_packets > 0 ? (float)total_bytes / total_packets : 0);
    printf("==================\n");
}

/**
 * @brief Signal handler for clean termination
 */
void handle_signal(int sig) {
    printf("\nReceived signal %d. Cleaning up...\n", sig);
    print_statistics();
    exit(0);
}

/**
 * @brief Initialize the signal handlers
 */
void init_signal_handlers() {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
}

/**
 * @brief Prints information about a captured packet.
 *
 * Parses the IP header of the captured packet and prints the source and destination
 * IP addresses, protocol type, and packet size.
 *
 * @param buffer The buffer containing the captured packet data.
 * @param size The size of the captured packet.
 * @param output_file The file to write packet details to.
 * @return int Returns 1 if max packets reached, 0 otherwise.
 */
int print_packet_info(const unsigned char *buffer, int size, const char *output_file, int max_packets) {
    // Skip Ethernet header (typically 14 bytes)
    const int ethernet_header_size = 14;
    
    // Ensure we have enough data for an IP header
    if (size <= ethernet_header_size) {
        printf("Packet too small to contain IP header\n");
        return 0;
    }
    
    // Point to the IP header (after Ethernet header)
    // First check if the packet is actually an IP packet
    if (size <= ethernet_header_size + 20) { // IP header is at least 20 bytes
        printf("Packet too small to be an IP packet\n");
        return 0;
    }
    
    // Check packet type from Ethernet header (EtherType field)
    uint16_t ether_type = ntohs(*((uint16_t *)(buffer + 12)));
    if (ether_type != 0x0800) { // 0x0800 is IP
        printf("Packet is not an IP packet (EtherType: 0x%04x)\n", ether_type);
        return 0;
    }
    
    struct ip *iph = (struct ip *)(buffer + ethernet_header_size);
    
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    
    source.sin_addr = iph->ip_src;
    dest.sin_addr = iph->ip_dst;
    
    // Get protocol name
    const char* protocol = get_protocol_name(iph->ip_p);
    
    char details[512];
    snprintf(details, sizeof(details),
             "========== Packet #%d ==========\n"
             "Source IP: %s\n"
             "Destination IP: %s\n"
             "Protocol: %s\n"
             "Packet Size: %d bytes\n"
             "Time: %s"
             "=====================================\n",
             total_packets + 1,
             inet_ntoa(source.sin_addr),
             inet_ntoa(dest.sin_addr),
             protocol,
             size,
             ctime(time(NULL)));
    
    printf("%s", details);
    
    FILE *output_file_ptr = fopen(output_file, "a");
    if (output_file_ptr) {
        fprintf(output_file_ptr, "%s", details);
        fclose(output_file_ptr);
    } else {
        fprintf(stderr, "Error opening output file: %s\n", output_file);
    }
    
    // Update statistics
    total_packets++;
    total_bytes += size;
    
    // Check if we've reached the maximum number of packets
    if (max_packets > 0 && total_packets >= max_packets) {
        printf("\nReached maximum packet count (%d). Stopping capture.\n", max_packets);
        print_statistics();
        return 1; // Signal to stop capturing
    }
    
    return 0; // Continue capturing
}