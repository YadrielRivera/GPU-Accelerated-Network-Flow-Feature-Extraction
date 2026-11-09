#ifndef PCAP_BATCHING_H
#define PCAP_BATCHING_H
#include <dirent.h>
#include <omp.h>
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
  uint32_t ts_usec;   // Timestamp microseconds (nanoseconds for 0xa1b23c4d)
  uint32_t incl_len;  // Number of bytes of packet saved in file
  uint32_t orig_len;  // Actual length of packet on the wire
} __attribute__((packed)) pcap_pkt_hdr_t;

// Per-packet metadata, one 32-byte record per packet (shared by host + GPU).
typedef struct {
  uint64_t offset;    // byte offset of the packet inside packet_data
  uint64_t ts_ns;     // capture timestamp, nanoseconds
  uint32_t caplen;    // bytes actually stored in packet_data (<= wire_len)
  uint32_t wire_len;  // length of the frame on the wire
  uint32_t file_id;   // index of the source pcap (keeps captures separate)
  uint32_t _pad;
} pkt_info_t;

// batches
extern uint8_t* packet_data;
extern pkt_info_t* packets;
extern size_t total_data_bytes;
extern size_t total_packets;
extern size_t data_capacity;    // Current allocated capacity for bytes
extern size_t packet_capacity;  // Current allocated capacity for packets

// Returns 0 = loaded, 1 = file skipped (unsupported/unreadable), -1 = out of
// memory (fatal).
int PcapRead(const char* pcap_file, uint32_t file_id);

// Returns 0 on success, non-zero on a fatal error.
int DatasetRead();

#endif
