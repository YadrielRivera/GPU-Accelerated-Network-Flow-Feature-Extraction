#include "../include/pcap_batching.h"
#include "../include/pcap_parsing.h"

// arguments: ./executable <CUDA_THREAD_NUMBER>
int main(int argc, char* argv[]) {
  MPI_Init(&argc, &argv);

  int my_rank, num_procs;
  MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
  MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

  // Each rank parses its own subset of files into its local buffers
  DatasetRead(my_rank, num_procs);

  printf("[Rank %d] Finished loading. Total packets on this rank: %zu\n",
         my_rank, total_packets);

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
  uint64_t* d_packet_ts;

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

  cudaError_t ts_stat =
      cudaMalloc(&d_packet_ts, sizeof(uint64_t) * total_packets);
  if (ts_stat != cudaSuccess) {
    printf("Cuda failed to allocate memory: %s\n", cudaGetErrorString(ts_stat));
    return 1;
  }

  pd_stat = cudaMemcpy(d_packet_data, packet_data, total_data_bytes,
                       cudaMemcpyHostToDevice);
  po_stat = cudaMemcpy(d_packet_offsets, packet_offsets,
                       total_packets * sizeof(int), cudaMemcpyHostToDevice);
  ts_stat = cudaMemcpy(d_packet_ts, packet_ts, total_packets * sizeof(uint64_t),
                       cudaMemcpyHostToDevice);

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

  if (ts_stat != cudaSuccess) {
    printf("Cuda failed to copy memory to the GPU: %s\n",
           cudaGetErrorString(ts_stat));
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
  PcapParallelParsing<<<cuda_block_count, threads_per_block>>>(
      d_packet_data, d_packet_offsets, d_packet_ts, total_packets,
      d_flow_table);

  cudaError_t kernel_stat = cudaDeviceSynchronize();
  if (kernel_stat != cudaSuccess) {
    printf("Kernel execution failed: %s\n", cudaGetErrorString(kernel_stat));
  }

    // Allocate host-side flow table buffer
  flow_record_t* h_flow_table = (flow_record_t*)malloc(sizeof(flow_record_t) * HASH_TABLE_SIZE);

  // Copy from device back to Host
  cudaError_t mcpy_stat = cudaMemcpy(h_flow_table, d_flow_table, sizeof(flow_record_t) * HASH_TABLE_SIZE, cudaMemcpyDeviceToHost);
  if (mcpy_stat != cudaSuccess) {
      printf("Failed to copy flow table back to host: %s\n", cudaGetErrorString(mcpy_stat));
  }

  // count the actual used values in the hash table
  int active_flows = 0;
  for (int i = 0; i < HASH_TABLE_SIZE; i++) {
      if (h_flow_table[i].state == SLOT_READY) {
          // This is a valid, aggregated flow record
          if (active_flows < 5) {
              const flow_record_t* f = &h_flow_table[i];
              printf("flow %u:%u -> %u:%u proto=%u pkts=%u bytes=%llu"
                     " len[min=%u max=%u] first=%llu last=%llu\n",
                     f->src_ip, f->src_port, f->dst_ip, f->dst_port, f->proto,
                     f->packet_count, (unsigned long long)f->byte_count,
                     f->min_pkt_len, f->max_pkt_len,
                     (unsigned long long)f->first_seen_ts,
                     (unsigned long long)f->last_seen_ts);
          }
          active_flows++;
      }
  }
  printf("Total unique flows detected: %d\n", active_flows);

  cudaFree(d_packet_data);
  cudaFree(d_packet_offsets);
  cudaFree(d_packet_ts);
  cudaFree(d_flow_table);
  MPI_Finalize();
  return 0;
}