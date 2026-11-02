#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

void __global__ ThreadParsing(uint8_t* d_packet_data, int* d_packet_offsets) {
  int th_idx = blockIdx.x * blockDim.x + threadIdx.x;

  if (th_idx >= total_packets) {
    return;
  }

  int offset = d_packet_offsets[th_idx];
  uint8_t* curr_pkt = d_packet_data + offset;

  uint16_t ethertype = (curr_pkt[12] << 8) | curr_pkt[13];

  switch (ethertype) {
    case IPv4:{
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
        const uint8_t* ip_header = cursor;
        uint8_t hdr_len = (ip_header[0] & 0x0F) * 4;
        const uint8_t* trnsprt_hdr = ip_header + hdr_len;

        uint32_t src_ip =
            ((uint32_t)ip_header[12] << 24) | ((uint32_t)ip_header[13] << 16) |
            ((uint32_t)ip_header[14] << 8) | (uint32_t)ip_header[15];
        uint32_t dst_ip =
            ((uint32_t)ip_header[16] << 24) | ((uint32_t)ip_header[17] << 16) |
            ((uint32_t)ip_header[18] << 8) | (uint32_t)ip_header[19];

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];
      } else if (current_ethertype == IPv6) {
        const uint8_t* ipv6_hdr = cursor;
        const uint8_t* trnsprt_hdr = ipv6_hdr + 40;

        uint16_t src_port = ((uint16_t)trnsprt_hdr[0] << 8) | trnsprt_hdr[1];
        uint16_t dst_port = ((uint16_t)trnsprt_hdr[2] << 8) | trnsprt_hdr[3];
      }
      break;
    }
    case PPPoE_SESSION: {}
      /*code*/
      break;
    case PPPoE_DISCOV: {}
      /*code*/
      break;
    case MLPS_UNI: {}
      /*code*/
      break;
    case MLPS_MULTI: {}
      /*code*/
      break;

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

  // call the kernel
  ThreadParsing<<<cuda_block_count, threads_per_block>>>(d_packet_data,
                                                         d_packet_offsets);

  cudaError_t kernel_stat = cudaDeviceSynchronize();
  if (kernel_stat != cudaSuccess) {
    printf("Kernel execution failed: %s\n", cudaGetErrorString(kernel_stat));
  }

  cudaFree(d_packet_data);
  cudaFree(d_packet_offsets);

  return 0;
}