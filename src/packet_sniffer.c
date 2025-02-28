/**
 * @file packet_sniffer.c
 * @brief Core functionality for capturing and analyzing network packets.
 *
 * Implements packet sniffing using libpcap, applies filters, and processes
 * captured packets to extract and log relevant information.
 */

 #include "headers.h"
 #include <pcap.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 
 #define BUFFER_SIZE 65536
 #define SNAP_LEN 1518    // Standard Ethernet frame max size
 
 char filter_exp[256] = "tcp or udp or icmp"; // Default filter expression
 
 /**
  * @brief Apply a filter to the packet capture handle.
  *
  * @param handle The pcap handle to apply the filter to.
  */
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
     pcap_freecode(&fp);  // Free the memory allocated by pcap_compile
 }
 
 /**
  * @brief List available network interfaces.
  */
 void list_interfaces() {
     char errbuf[PCAP_ERRBUF_SIZE];
     pcap_if_t *alldevs, *dev;
     
     if (pcap_findalldevs(&alldevs, errbuf) == -1) {
         fprintf(stderr, "Error finding devices: %s\n", errbuf);
         return;
     }
     
     printf("\nAvailable Network Interfaces:\n");
     printf("-----------------------------\n");
     
     int i = 0;
     for (dev = alldevs; dev != NULL; dev = dev->next) {
         printf("%d. %s", ++i, dev->name);
         if (dev->description) {
             printf(" (%s)", dev->description);
         } else {
             printf(" (No description available)");
         }
         printf("\n");
     }
     printf("-----------------------------\n");
     
     pcap_freealldevs(alldevs);
 }
 
 /**
  * @brief Starts the packet sniffer.
  *
  * Opens a network interface, applies filters, and captures packets.
  *
  * @param output_file The name of the file to write packet details to.
  * @param max_packets Maximum number of packets to capture (0 for unlimited).
  * @return int Returns 1 on success, 0 on failure.
  */
 int start_sniffer(const char *output_file, int max_packets) {
     char errbuf[PCAP_ERRBUF_SIZE];
     pcap_t *handle;
     struct pcap_pkthdr header;
     const unsigned char *packet;
 
     // List available interfaces first
     list_interfaces();
     
     // Find available devices
     pcap_if_t *alldevs;
     if (pcap_findalldevs(&alldevs, errbuf) == -1) {
         fprintf(stderr, "Error finding devices: %s\n", errbuf);
         return 0;
     }
     
     if (alldevs == NULL) {
         fprintf(stderr, "No devices found. Make sure you have permission.\n");
         return 0;
     }
 
     char *device = alldevs->name;
     printf("Using device: %s\n", device);
 
     // Open the device for capturing
     handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
     if (handle == NULL) {
         fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
         pcap_freealldevs(alldevs);
         return 0;
     }
     
     // Check if the link layer is Ethernet
     int datalink = pcap_datalink(handle);
     if (datalink != DLT_EN10MB) {
         fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
         pcap_close(handle);
         pcap_freealldevs(alldevs);
         return 0;
     }
 
     // Initialize signal handlers
     init_signal_handlers();
     
     // Apply filter
     apply_filter(handle);
 
     // Clear the output file
     FILE *file = fopen(output_file, "w");
     if (file) {
         fprintf(file, "PacketProwler Capture Started: %s", ctime(time(NULL)));
         fprintf(file, "Interface: %s\n", device);
         fprintf(file, "Filter: %s\n\n", filter_exp);
         fclose(file);
     }
 
     printf("\nListening for packets... (Press Ctrl+C to stop)\n");
     printf("Logging to: %s\n", output_file);
     if (max_packets > 0) {
         printf("Will capture %d packets and then stop\n", max_packets);
     } else {
         printf("Will capture packets until manually stopped\n");
     }
     
     int stop_capture = 0;
     
     // Main capture loop
     while (!stop_capture && (packet = pcap_next(handle, &header)) != NULL) {
         // Process the packet and check if we should stop
         stop_capture = print_packet_info(packet, header.len, output_file, max_packets);
     }
 
     // Clean up
     pcap_close(handle);
     pcap_freealldevs(alldevs);
     printf("\nPacket capture complete.\n");
     return 1;
 }