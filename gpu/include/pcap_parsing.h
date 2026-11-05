#ifndef PCAP_PARSING_H
#define PCAP_PARSING_H

#include <inttypes.h>
#include <stdlib.h>

#include "pcap_batching.h"

// ethernet types
#define IPv4 0x0800
#define ARP 0x0806
#define IPv6 0x86DD
#define VLAN_TAG 0x8100
#define QINQ_TAG 0x88A8
#define PPPoE_DISCOV 0x8863
#define PPPoE_SESSION 0x8864
#define MLPS_UNI 0x8847
#define MLPS_MULTI 0x8848

// IP protocol types
#define ICMP 1
#define TCP 6
#define UDP 17
#define SCTP 132

// arp operations
#define ARP_REQ 1
#define ARP_REP 2

// Hashing
#define HASH_TABLE_SIZE (1 << 20)
#define HASH_MASK (HASH_TABLE_SIZE - 1)
#define SLOT_EMPTY 0
#define SLOT_WRITING 1
#define SLOT_READY 2

// Flow identity. Addresses are stored in full (IPv4 in word 0, rest zero) so
// distinct IPv6 hosts never collide, and file_id keeps unrelated captures from
// merging when they reuse the same private addresses.
typedef struct {
  uint32_t file_id;
  uint32_t src_ip[4];
  uint32_t dst_ip[4];
  uint16_t src_port;  // 0 unless TCP/UDP/SCTP
  uint16_t dst_port;
  uint8_t proto;   // final upper-layer protocol (after IPv6 ext. headers)
  uint8_t ip_ver;  // 4 or 6
} flow_key_t;

typedef struct __align__(8) {
  uint32_t state;
  flow_key_t key;  // written once by the slot owner
  // aggregates (atomics)
  uint32_t packet_count;
  uint32_t min_pkt_len;
  uint32_t max_pkt_len;
  uint64_t byte_count;
  uint64_t first_seen_ts;  // ns
  uint64_t last_seen_ts;   // ns
}
flow_record_t;

// Every packet lands in exactly one bucket, so for each rank:
//   sum(packet_count) + non_flow + malformed + table_full == total_packets
typedef struct {
  unsigned long long non_flow;    // ARP, PPPoE discovery, unknown ethertype...
  unsigned long long malformed;   // truncated or invalid headers
  unsigned long long table_full;  // no free slot in the hash table
} parse_stats_t;

__device__ uint32_t HashKey(const flow_key_t& key);

// Returns false only if the table is full.
__device__ bool AggregateFlow(flow_record_t* table, const flow_key_t& key,
                              uint32_t pkt_len, uint64_t ts);

// Parses the IP header at l3 (bounds-checked against pkt + caplen).
// Returns false if the packet is truncated or malformed.
__device__ bool ParseIP(const uint8_t* pkt, uint32_t caplen, const uint8_t* l3,
                        flow_key_t* key);

__global__ void PcapParallelParsing(const uint8_t* d_packet_data,
                                    const pkt_info_t* d_packets,
                                    size_t d_total_packets,
                                    flow_record_t* d_flow_table,
                                    parse_stats_t* d_stats);

#endif