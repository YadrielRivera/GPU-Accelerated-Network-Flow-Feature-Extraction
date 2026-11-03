#include <stdint.h>
#include <stdio.h>

#include "../pcap_pre-proc/pcap_parse.c"

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

typedef struct __align__(8) {
  uint32_t locked;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
  uint32_t packet_count;
  uint64_t byte_count;
} flow_record_t;

// FNV-1a hashing
__device__ uint32_t HashTuple(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint8_t proto) {
  uint32_t hash = 2166136261UL;

  hash ^= src_ip;
  hash *= 16777619UL;
  hash ^= dst_ip;
  hash *= 16777619UL;
  hash ^= ((uint32_t)src_port << 16) | dst_port;
  hash *= 16777619UL;
  hash ^= proto;
  hash *= 16777619UL;

  return hash;
}

__device__ void aggregate_flow(flow_record_t* table, uint32_t src_ip,
                               uint32_t dst_ip, uint16_t src_port,
                               uint16_t dst_port, uint8_t proto,
                               uint32_t pkt_len) {
  uint32_t hash = HashTuple(src_ip, dst_ip, src_port, dst_port, proto);
  uint32_t idx = hash & HASH_MASK;

  while (true) {
    if (table[idx].src_ip == src_ip && table[idx].dst_ip == dst_ip &&
        table[idx].src_port == src_port && table[idx].dst_port == dst_port &&
        table[idx].proto == proto) {
      // Existing flow found! Atomically update counters
      atomicAdd(&(table[idx].packet_count), 1);
      atomicAdd((unsigned long long*)&(table[idx].byte_count),
                (unsigned long long)pkt_len);
      return;
    }

    // Check if the slot is completely empty (src_ip == 0 and unowned)
    if (table[idx].src_ip == 0) {
      // Attempt to acquire the bucket lock via atomicCAS
      if (atomicCAS(&(table[idx].locked), 0, 1) == 0) {
        // Double check emptiness after acquiring lock
        if (table[idx].src_ip == 0) {
          table[idx].src_ip = src_ip;
          table[idx].dst_ip = dst_ip;
          table[idx].src_port = src_port;
          table[idx].dst_port = dst_port;
          table[idx].proto = proto;
          table[idx].packet_count = 1;
          table[idx].byte_count = pkt_len;

          // Release lock
          atomicExch(&(table[idx].locked), 0);
          return;
        }
        // Release lock if another thread beat us to it
        atomicExch(&(table[idx].locked), 0);
      }
    }
    // linear probing
    idx = (idx + 1) & HASH_MASK;
  }
}

__device__ uint32_t fold_ipv6(const uint8_t* a) {
  uint32_t r = 0;
  #pragma unroll
  for (int w = 0; w < 4; w++) {
    r ^= ((uint32_t)a[w*4]   << 24) |
         ((uint32_t)a[w*4+1] << 16) |
         ((uint32_t)a[w*4+2] << 8)  |
         ((uint32_t)a[w*4+3]);
  }
  return r;
}

void __global__ ThreadParsing(uint8_t* d_packet_data, int* d_packet_offsets,
                              int d_total_packets,
                              flow_record_t* d_flow_table) {
  int th_idx = blockIdx.x * blockDim.x + threadIdx.x;

  if (th_idx >= d_total_packets) {
    return;
  }

  int offset = d_packet_offsets[th_idx];
  uint8_t* curr_pkt = d_packet_data + offset;

  uint16_t ethertype = (curr_pkt[12] << 8) | curr_pkt[13];

  switch (ethertype) {
    case IPv4: {
      const uint8_t* ip_header = curr_pkt + 14;
      uint8_t protocol = ip_header[9];

      uint32_t src_ip =
          ((uint32_t)ip_header[12] << 24) | ((uint32_t)ip_header[13] << 16) |
          ((uint32_t)ip_header[14] << 8) | ((uint32_t)ip_header[15]);
      uint32_t dst_ip =
          ((uint32_t)ip_header[16] << 24) | ((uint32_t)ip_header[17] << 16) |
          ((uint32_t)ip_header[18] << 8) | ((uint32_t)ip_header[19]);

      uint8_t hdr_len = (ip_header[0] & 0x0F) * 4;
      const uint8_t* trnsprt_hdr = ip_header + hdr_len;

      uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
      uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

      uint16_t ip_total_len = ((uint16_t)ip_header[2] << 8) | ip_header[3];
      uint32_t pkt_len = (uint32_t)(ip_header - curr_pkt) + ip_total_len;
      aggregate_flow(d_flow_table, src_ip, dst_ip, src_port, dst_port, protocol,
                     pkt_len);

      break;
    }
    case ARP: {
      uint8_t* arp_hdr = curr_pkt + 14;

      uint16_t hw_type = ((uint16_t)arp_hdr[0] << 8) | arp_hdr[1];
      uint16_t proto_type = ((uint16_t)arp_hdr[2] << 8) | arp_hdr[3];
      uint16_t operation =
          ((uint16_t)arp_hdr[6] << 8) | arp_hdr[7];  // 1 = Request, 2 = Reply

      if (hw_type == 1 && proto_type == IPv4) {
        uint32_t sender_ip =
            ((uint32_t)arp_hdr[14] << 24) | ((uint32_t)arp_hdr[15] << 16) |
            ((uint32_t)arp_hdr[16] << 8) | (uint32_t)arp_hdr[17];

        uint32_t target_ip =
            ((uint32_t)arp_hdr[24] << 24) | ((uint32_t)arp_hdr[25] << 16) |
            ((uint32_t)arp_hdr[26] << 8) | (uint32_t)arp_hdr[27];
      }
      break;
    }
    case IPv6: {
      const uint8_t* ipv6_hdr = curr_pkt + 14;

      uint8_t next_hdr = ipv6_hdr[6];

      const uint8_t* src_ipv6 = ipv6_hdr + 8;

      const uint8_t* dst_ipv6 = ipv6_hdr + 24;

      const uint8_t* trnsprt_hdr = ipv6_hdr + 40;

      uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
      uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

      uint32_t src_ip_folded = fold_ipv6(src_ipv6);
      uint32_t dst_ip_folded = fold_ipv6(dst_ipv6);
      uint16_t ipv6_payload_len = ((uint16_t)ipv6_hdr[4] << 8) | ipv6_hdr[5];
      uint32_t pkt_len =
          (uint32_t)(ipv6_hdr - curr_pkt) + 40 + ipv6_payload_len;
      aggregate_flow(d_flow_table, src_ip_folded, dst_ip_folded, src_port,
                     dst_port, next_hdr, pkt_len);
      break;
    }
    case VLAN_TAG: {
      const uint8_t* cursor = curr_pkt + 14;
      uint16_t current_ethertype = ethertype;
      bool parsing_payload = false;

      while (!parsing_payload) {
        switch (current_ethertype) {
          case VLAN_TAG: {
            uint16_t tci = ((uint16_t)cursor[0] << 8) | cursor[1];
            uint16_t vlan_id = tci & 0x0FFF;

            current_ethertype = ((uint16_t)cursor[2] << 8) | cursor[3];
            cursor += 4;  // Advance past VLAN tag
            break;
          }
          case IPv4:
          case IPv6:
          case ARP:
            parsing_payload = true;
            break;
          default:
            parsing_payload = true;
            current_ethertype = 0;  // Unsupported inner protocol
            break;
        }
      }
      if (current_ethertype == IPv4) {
        const uint8_t* ip_hdr = cursor;
        uint8_t hdr_len = (ip_hdr[0] & 0x0F) * 4;
        const uint8_t* trnsprt_hdr = ip_hdr + hdr_len;

        uint32_t src_ip = ((uint32_t)ip_hdr[12] << 24) |
                          ((uint32_t)ip_hdr[13] << 16) |
                          ((uint32_t)ip_hdr[14] << 8) | (uint32_t)ip_hdr[15];
        uint32_t dst_ip = ((uint32_t)ip_hdr[16] << 24) |
                          ((uint32_t)ip_hdr[17] << 16) |
                          ((uint32_t)ip_hdr[18] << 8) | (uint32_t)ip_hdr[19];

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

        uint16_t ip_total_len = ((uint16_t)ip_hdr[2] << 8) | ip_hdr[3];
        uint32_t pkt_len = (uint32_t)(ip_hdr - curr_pkt) + ip_total_len;
        aggregate_flow(d_flow_table, src_ip, dst_ip, src_port, dst_port,
                       ip_hdr[9], pkt_len);

      } else if (current_ethertype == IPv6) {
        const uint8_t* ipv6_hdr = cursor;
        const uint8_t* trnsprt_hdr = ipv6_hdr + 40;

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

        const uint8_t* src_ipv6 = ipv6_hdr + 8;

        const uint8_t* dst_ipv6 = ipv6_hdr + 24;

        uint32_t src_ip_folded = fold_ipv6(src_ipv6);
        uint32_t dst_ip_folded = fold_ipv6(dst_ipv6);
        uint16_t ipv6_payload_len = ((uint16_t)ipv6_hdr[4] << 8) | ipv6_hdr[5];
        uint32_t pkt_len =
            (uint32_t)(ipv6_hdr - curr_pkt) + 40 + ipv6_payload_len;
        aggregate_flow(d_flow_table, src_ip_folded, dst_ip_folded, src_port,
                       dst_port, ipv6_hdr[6], pkt_len);
      }
      break;
    }
    case PPPoE_SESSION: {
      uint8_t* ses_hdr = curr_pkt + 14;

      uint8_t ver_type = ses_hdr[0];
      uint8_t code = ses_hdr[1];
      uint16_t ses_id = ((uint16_t)ses_hdr[2] << 8) | ses_hdr[3];
      uint16_t len = ((uint16_t)ses_hdr[4] << 8) | ses_hdr[5];
      uint16_t pproc = ((uint16_t)ses_hdr[6] << 8) | ses_hdr[7];

      const uint8_t* ip_hdr = ses_hdr + 8;
      // IPv4
      if (pproc == 0x0021) {
        uint8_t protocol = ip_hdr[9];

        uint32_t src_ip = ((uint32_t)ip_hdr[12] << 24) |
                          ((uint32_t)ip_hdr[13] << 16) |
                          ((uint32_t)ip_hdr[14] << 8) | ((uint32_t)ip_hdr[15]);
        uint32_t dst_ip = ((uint32_t)ip_hdr[16] << 24) |
                          ((uint32_t)ip_hdr[17] << 16) |
                          ((uint32_t)ip_hdr[18] << 8) | ((uint32_t)ip_hdr[19]);

        uint8_t hdr_len = (ip_hdr[0] & 0x0F) * 4;
        const uint8_t* trnsprt_hdr = ip_hdr + hdr_len;

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

        uint16_t ip_total_len = ((uint16_t)ip_hdr[2] << 8) | ip_hdr[3];
        uint32_t pkt_len = (uint32_t)(ip_hdr - curr_pkt) + ip_total_len;
        aggregate_flow(d_flow_table, src_ip, dst_ip, src_port, dst_port,
                       protocol, pkt_len);
      }
      // IPv6
      if (pproc == 0x0057) {
        uint8_t next_hdr = ip_hdr[6];

        const uint8_t* src_ipv6 = ip_hdr + 8;

        const uint8_t* dst_ipv6 = ip_hdr + 24;

        const uint8_t* trnsprt_hdr = ip_hdr + 40;

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

        uint32_t src_ip_folded = fold_ipv6(src_ipv6);
        uint32_t dst_ip_folded = fold_ipv6(dst_ipv6);
        uint16_t ipv6_payload_len = ((uint16_t)ip_hdr[4] << 8) | ip_hdr[5];
        uint32_t pkt_len =
            (uint32_t)(ip_hdr - curr_pkt) + 40 + ipv6_payload_len;
        aggregate_flow(d_flow_table, src_ip_folded, dst_ip_folded, src_port,
                       dst_port, next_hdr, pkt_len);
      }
      break;
    }
    case PPPoE_DISCOV: {
      // parse, but we don't use it because
      // it wont produce 5-tuples
      // this section is just to avoid crashing
      const uint8_t* disc_hdr = curr_pkt + 14;

      uint8_t ver_type = disc_hdr[0];
      uint8_t code = disc_hdr[1];
      uint16_t ses_id = ((uint16_t)disc_hdr[2] << 8) |
                        disc_hdr[3];  // Usually 0x0000 during discovery
      uint16_t pyld_len = ((uint16_t)disc_hdr[4] << 8) | disc_hdr[5];

      break;
    }
    case MLPS_UNI:
    case MLPS_MULTI: {
      const uint8_t* cursor = curr_pkt + 14;
      bool bottom_of_stack = false;

      // Iteratively strip MPLS label stack
      while (!bottom_of_stack) {
        uint32_t mpls_entry = ((uint32_t)cursor[0] << 24) |
                              ((uint32_t)cursor[1] << 16) |
                              ((uint32_t)cursor[2] << 8) | (uint32_t)cursor[3];

        if (cursor[2] & 0x01) {
          bottom_of_stack = true;
        }

        cursor += 4;
      }

      uint8_t ip_version = cursor[0] >> 4;

      if (ip_version == 4) {
        const uint8_t* ip_hdr = cursor;
        uint8_t hdr_len = (ip_hdr[0] & 0x0F) * 4;
        const uint8_t* trnsprt_hdr = ip_hdr + hdr_len;

        uint32_t src_ip = ((uint32_t)ip_hdr[12] << 24) |
                          ((uint32_t)ip_hdr[13] << 16) |
                          ((uint32_t)ip_hdr[14] << 8) | (uint32_t)ip_hdr[15];
        uint32_t dst_ip = ((uint32_t)ip_hdr[16] << 24) |
                          ((uint32_t)ip_hdr[17] << 16) |
                          ((uint32_t)ip_hdr[18] << 8) | (uint32_t)ip_hdr[19];

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

        uint16_t ip_total_len = ((uint16_t)ip_hdr[2] << 8) | ip_hdr[3];
        uint32_t pkt_len = (uint32_t)(ip_hdr - curr_pkt) + ip_total_len;
        aggregate_flow(d_flow_table, src_ip, dst_ip, src_port, dst_port,
                       ip_hdr[9], pkt_len);

      } else if (ip_version == 6) {
        const uint8_t* ipv6_hdr = cursor;
        const uint8_t* trnsprt_hdr = ipv6_hdr + 40;

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];

        const uint8_t* src_ipv6 = ipv6_hdr + 8;

        const uint8_t* dst_ipv6 = ipv6_hdr + 24;

        uint32_t src_ip_folded = fold_ipv6(src_ipv6);
        uint32_t dst_ip_folded = fold_ipv6(dst_ipv6);
        uint16_t ipv6_payload_len = ((uint16_t)ipv6_hdr[4] << 8) | ipv6_hdr[5];
        uint32_t pkt_len =
            (uint32_t)(ipv6_hdr - curr_pkt) + 40 + ipv6_payload_len;
        aggregate_flow(d_flow_table, src_ip_folded, dst_ip_folded, src_port,
                       dst_port, ipv6_hdr[6], pkt_len);
      }
      break;
    }
    default:
      break;
  }
}

int main(int argc, char* argv[]) {
  int threads_per_block = 1024;
  int cuda_block_count =
      (total_packets + threads_per_block - 1) / threads_per_block;

  if (argc >= 2) {
    threads_per_block = atoi(argv[1]);
    cuda_block_count =
        (total_packets + threads_per_block - 1) / threads_per_block;
  }

  uint8_t* d_packet_data;
  int* d_packet_offsets;

  cudaError_t pd_stat =
      cudaMalloc(&d_packet_data, sizeof(uint8_t) * data_capacity);
  if (pd_stat != cudaSuccess) {
    printf("Cuda failed to allocate memory: %s\n", cudaGetErrorString(pd_stat));
    return 1;
  }

  cudaError_t po_stat =
      cudaMalloc(&d_packet_offsets, sizeof(int) * total_packets);
  if (po_stat != cudaSuccess) {
    printf("Cuda failed to allocate memory: %s\n", cudaGetErrorString(po_stat));
    return 1;
  }

  pd_stat = cudaMemcpy(d_packet_data, packet_data, total_data_bytes,
                       cudaMemcpyHostToDevice);
  po_stat = cudaMemcpy(d_packet_offsets, packet_offsets,
                       total_packets * sizeof(int), cudaMemcpyHostToDevice);

  if (pd_stat != cudaSuccess) {
    printf("Cuda failed to copy memory to the GPU: %s\n",
           cudaGetErrorString(pd_stat));
    return 1;
  }

  if (po_stat != cudaSuccess) {
    printf("Cuda failed to copy memory to the GPU: %s\n",
           cudaGetErrorString(po_stat));
    return 1;
  }

  flow_record_t* d_flow_table;
  cudaError_t ft_stat =
      cudaMalloc(&d_flow_table, sizeof(flow_record_t) * HASH_TABLE_SIZE);
  if (ft_stat != cudaSuccess) {
    printf("Cuda failed to allocate hash table: %s\n",
           cudaGetErrorString(ft_stat));
    return 1;
  }
  cudaMemset(d_flow_table, 0, sizeof(flow_record_t) * HASH_TABLE_SIZE);

  // call the kernel
  ThreadParsing<<<cuda_block_count, threads_per_block>>>(
      d_packet_data, d_packet_offsets, total_packets, d_flow_table);

  cudaError_t kernel_stat = cudaDeviceSynchronize();
  if (kernel_stat != cudaSuccess) {
    printf("Kernel execution failed: %s\n", cudaGetErrorString(kernel_stat));
  }

  cudaFree(d_packet_data);
  cudaFree(d_packet_offsets);
  cudaFree(d_flow_table);
  return 0;
}