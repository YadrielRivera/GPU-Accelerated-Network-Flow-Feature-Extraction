#ifndef PCAP_PARSING_H
#define PCAP_PARSING_H

#include <inttypes.h>
#include <stdlib.h>

// ethernet types
#define IPv4 0x0800
#define ARP 0x0806
#define IPv6 0x86DD
#define VLAN_TAG 0x8100
#define PPPoE_DISCOV 0x8863
#define PPPoE_SESSION 0x8864
#define MLPS_UNI 0x8847
#define MLPS_MULTI 0x8848

// IP protocol types
#define TCP 6
#define UDP 17
#define ICMP 1

// arp operations
#define ARP_REQ 1
#define ARP_REP 2

// Hashing
#define HASH_TABLE_SIZE (1 << 20)
#define HASH_MASK (HASH_TABLE_SIZE - 1)
#define SLOT_EMPTY 0
#define SLOT_WRITING 1
#define SLOT_READY 2

typedef struct __align__(8) {
  uint32_t state;
  // 5-tuple (written once by the slot owner)
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
  // aggregates (atomics)
  uint32_t packet_count;
  uint32_t min_pkt_len;
  uint32_t max_pkt_len;
  uint64_t byte_count;
  uint64_t first_seen_ts;  // ns
  uint64_t last_seen_ts;   // ns
}
flow_record_t;

__device__ uint32_t HashTuple(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint8_t proto);

__device__ void AggregateFlow(flow_record_t* table, uint32_t src_ip,
                              uint32_t dst_ip, uint16_t src_port,
                              uint16_t dst_port, uint8_t proto,
                              uint32_t pkt_len, uint64_t ts);

__device__ uint32_t fold_ipv6(const uint8_t* a);

void __global__ PcapParallelParsing(uint8_t* d_packet_data,
                                    int* d_packet_offsets,
                                    uint64_t* d_packet_ts, int d_total_packets,
                                    flow_record_t* d_flow_table);

#endif