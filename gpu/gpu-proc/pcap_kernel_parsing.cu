#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <math.h>
#include "../pcap_pre-proc/pcap_parse.c"

void __global__ ThreadParsing(uint8_t* d_packet_data, int* d_packet_offsets){
  int th_idx = blockIdx.x * blockDim.x + threadIdx.x;
  printf("Threading...\n");
}

int main(int argc, char* argv[]){
  int threads_per_block = 1024;
  int cuda_block_count = (total_packets + threads_per_block - 1) / threads_per_block;

  if (argc >= 2){
    threads_per_block = atoi(argv[1]);
    cuda_block_count = (total_packets + threads_per_block - 1) / threads_per_block;
  }

  uint8_t* d_packet_data;
  int* d_packet_offsets;

  cudaError_t pd_stat = cudaMalloc(&d_packet_data, sizeof(uint8_t)*data_capacity);
  if (pd_stat != cudaSuccess){
    printf("Cuda failed to allocate memory: %s\n", cudaGetErrorString(pd_stat));
    return 1;
  }

  cudaError_t po_stat = cudaMalloc(&d_packet_offsets, sizeof(int)*total_packets);
  if (po_stat != cudaSuccess){
    printf("Cuda failed to allocate memory: %s\n", cudaGetErrorString(po_stat));
    return 1;
  }

  pd_stat = cudaMemcpy(d_packet_data, packet_data, total_data_bytes, cudaMemcpyHostToDevice);
  po_stat = cudaMemcpy(d_packet_offsets, packet_offsets, total_packets*sizeof(int), cudaMemcpyHostToDevice);

  if (pd_stat != cudaSuccess){
    printf("Cuda failed to copy memory to the GPU: %s\n", cudaGetErrorString(pd_stat));
    return 1;
  }

  if (po_stat != cudaSuccess){
    printf("Cuda failed to copy memory to the GPU: %s\n", cudaGetErrorString(po_stat));
    return 1;
  }

  // call the kernel
  ThreadParsing<<<cuda_block_count, threads_per_block>>>(d_packet_data, d_packet_offsets);

  cudaError_t kernel_stat = cudaDeviceSynchronize();
  if (kernel_stat != cudaSuccess){
    printf("Kernel execution failed: %s\n", cudaGetErrorString(kernel_stat));
  }

  cudaFree(d_packet_data);
  cudaFree(d_packet_offsets);

  return 0;
}