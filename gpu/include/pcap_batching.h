#ifndef PCAP_BATCHING_H
#define PCAP_BATCHING_H
#include <dirent.h>
#include <mpi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// PCAP global header
typedef struct {
  uint32_t magic_number;   // number identifying PCAP format
  uint16_t version_major;  // Major version number
  uint16_t version_minor;  // Minor version number
  int32_t thiszone;        // GMT to local correction
  uint32_t sigfigs;        // Accuracy of timestamps
  uint32_t snaplen;        // Max length of captured packets
  uint32_t network;        // Data link type
} __attribute__((packed)) pcap_hdr_t;

// PCAP packet header
typedef struct {
  uint32_t ts_sec;    // Timestamp seconds
  uint32_t ts_usec;   // Timestamp microseconds
  uint32_t incl_len;  // Number of bytes of packet saved in file
  uint32_t orig_len;  // Actual length of packet on the wire
} __attribute__((packed)) pcap_pkt_hdr_t;

#ifdef __cplusplus
extern "C" {
#endif

// batches
extern uint8_t* packet_data;
extern int* packet_offsets;
extern size_t total_data_bytes;
extern size_t total_packets;
extern size_t data_capacity;    // Current allocated capacity for bytes
extern size_t packet_capacity;  // Current allocated capacity for offsets

int PcapRead(char pcap_file[]);

int DatasetRead(int my_rank, int num_procs);
#ifdef __cplusplus
}
#endif
#endif
