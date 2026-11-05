#include "../include/pcap_batching.h"
#include "../include/pcap_parsing.h"

// Needs a local variable `my_rank` and `rc`, and a `cleanup:` label.
#define CUDA_CHECK(call)                                                  \
  do {                                                                    \
    cudaError_t err_ = (call);                                            \
    if (err_ != cudaSuccess) {                                            \
      fprintf(stderr, "[Rank %d] CUDA error at %s:%d: %s\n", my_rank,     \
              __FILE__, __LINE__, cudaGetErrorString(err_));              \
      rc = 1;                                                             \
      goto cleanup;                                                       \
    }                                                                     \
  } while (0)

static void FormatIP(const flow_key_t* k, const uint32_t* a, char* buf,
                     size_t n) {
  if (k->ip_ver == 4) {
    snprintf(buf, n, "%u.%u.%u.%u", a[0] >> 24, (a[0] >> 16) & 0xFF,
             (a[0] >> 8) & 0xFF, a[0] & 0xFF);
  } else {
    snprintf(buf, n, "%x:%x:%x:%x:%x:%x:%x:%x", a[0] >> 16, a[0] & 0xFFFF,
             a[1] >> 16, a[1] & 0xFFFF, a[2] >> 16, a[2] & 0xFFFF, a[3] >> 16,
             a[3] & 0xFFFF);
  }
}

// Does all the per-rank work. Returns 0 on success. Every exit goes through
// `cleanup`, so main() always reaches MPI_Finalize.
static int RunRank(int my_rank, int num_procs, int threads_per_block) {
  // All declarations up front: a goto may not jump over an initialisation.
  int rc = 0;
  int local_rank = 0, dev_count = 0;
  MPI_Comm local_comm;
  uint8_t* d_packet_data = NULL;
  pkt_info_t* d_packets = NULL;
  flow_record_t* d_flow_table = NULL;
  parse_stats_t* d_stats = NULL;
  flow_record_t* h_flow_table = NULL;
  parse_stats_t h_stats;
  size_t cuda_block_count = 0;
  size_t active_flows = 0, packets_in_flows = 0, bad_records = 0;
  size_t accounted = 0;
  const size_t table_bytes = sizeof(flow_record_t) * (size_t)HASH_TABLE_SIZE;

  // One GPU per rank on its node (collective: every rank must reach this).
  MPI_Comm_split_type(MPI_COMM_WORLD, MPI_COMM_TYPE_SHARED, my_rank,
                      MPI_INFO_NULL, &local_comm);
  MPI_Comm_rank(local_comm, &local_rank);
  MPI_Comm_free(&local_comm);

  CUDA_CHECK(cudaGetDeviceCount(&dev_count));
  if (dev_count == 0) {
    fprintf(stderr, "[Rank %d] no CUDA device found\n", my_rank);
    rc = 1;
    goto cleanup;
  }
  CUDA_CHECK(cudaSetDevice(local_rank % dev_count));

  // Each rank parses its own subset of files into its local buffers
  if (DatasetRead(my_rank, num_procs) != 0) {
    rc = 1;
    goto cleanup;
  }
  printf("[Rank %d] Finished loading. Total packets on this rank: %zu\n",
         my_rank, total_packets);

  if (total_packets == 0) {
    printf("[Rank %d] nothing to process\n", my_rank);
    goto cleanup;
  }

  CUDA_CHECK(cudaMalloc(&d_packet_data, total_data_bytes));
  CUDA_CHECK(cudaMalloc(&d_packets, sizeof(pkt_info_t) * total_packets));
  CUDA_CHECK(cudaMalloc(&d_flow_table, table_bytes));
  CUDA_CHECK(cudaMalloc(&d_stats, sizeof(parse_stats_t)));

  CUDA_CHECK(cudaMemcpy(d_packet_data, packet_data, total_data_bytes,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(d_packets, packets,
                        sizeof(pkt_info_t) * total_packets,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemset(d_flow_table, 0, table_bytes));
  CUDA_CHECK(cudaMemset(d_stats, 0, sizeof(parse_stats_t)));

  cuda_block_count = (total_packets + threads_per_block - 1) / threads_per_block;
  PcapParallelParsing<<<(unsigned int)cuda_block_count, threads_per_block>>>(
      d_packet_data, d_packets, total_packets, d_flow_table, d_stats);
  CUDA_CHECK(cudaGetLastError());       // launch errors
  CUDA_CHECK(cudaDeviceSynchronize());  // execution errors

  h_flow_table = (flow_record_t*)malloc(table_bytes);
  if (h_flow_table == NULL) {
    fprintf(stderr, "[Rank %d] out of host memory for the flow table\n",
            my_rank);
    rc = 1;
    goto cleanup;
  }
  CUDA_CHECK(cudaMemcpy(h_flow_table, d_flow_table, table_bytes,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaMemcpy(&h_stats, d_stats, sizeof(parse_stats_t),
                        cudaMemcpyDeviceToHost));

  for (size_t i = 0; i < (size_t)HASH_TABLE_SIZE; i++) {
    const flow_record_t* f = &h_flow_table[i];
    if (f->state != SLOT_READY) continue;

    if (f->packet_count == 0 || f->min_pkt_len > f->max_pkt_len ||
        f->first_seen_ts > f->last_seen_ts) {
      bad_records++;
    }

    if (active_flows < 5) {
      char src[48], dst[48];
      FormatIP(&f->key, f->key.src_ip, src, sizeof(src));
      FormatIP(&f->key, f->key.dst_ip, dst, sizeof(dst));
      printf(
          "[Rank %d] flow file=%u %s:%u -> %s:%u proto=%u pkts=%u bytes=%llu"
          " len[min=%u max=%u] first=%llu last=%llu\n",
          my_rank, f->key.file_id, src, f->key.src_port, dst, f->key.dst_port,
          f->key.proto, f->packet_count, (unsigned long long)f->byte_count,
          f->min_pkt_len, f->max_pkt_len, (unsigned long long)f->first_seen_ts,
          (unsigned long long)f->last_seen_ts);
    }
    packets_in_flows += f->packet_count;
    active_flows++;
  }

  accounted = packets_in_flows + h_stats.non_flow + h_stats.malformed +
              h_stats.table_full;
  printf("[Rank %d] Total unique flows detected: %zu\n", my_rank, active_flows);
  printf(
      "[Rank %d] packets: total=%zu in_flows=%zu non_flow=%llu malformed=%llu"
      " table_full=%llu -> %s\n",
      my_rank, total_packets, packets_in_flows, h_stats.non_flow,
      h_stats.malformed, h_stats.table_full,
      accounted == total_packets ? "all accounted for" : "MISMATCH");
  if (h_stats.table_full > 0) {
    fprintf(stderr,
            "[Rank %d] WARNING: flow table full, %llu packets were dropped\n",
            my_rank, h_stats.table_full);
  }
  if (bad_records > 0) {
    fprintf(stderr, "[Rank %d] WARNING: %zu flow records failed sanity checks\n",
            my_rank, bad_records);
  }

cleanup:
  cudaFree(d_packet_data);
  cudaFree(d_packets);
  cudaFree(d_flow_table);
  cudaFree(d_stats);
  free(h_flow_table);
  free(packet_data);
  free(packets);
  packet_data = NULL;
  packets = NULL;
  return rc;
}

// arguments: ./executable <CUDA_THREAD_NUMBER>
int main(int argc, char* argv[]) {
  MPI_Init(&argc, &argv);

  int my_rank, num_procs;
  MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
  MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

  int threads_per_block = 1024;
  if (argc >= 2) {
    int t = atoi(argv[1]);
    if (t >= 1 && t <= 1024) {
      threads_per_block = t;
    } else if (my_rank == 0) {
      fprintf(stderr, "Ignoring invalid thread count '%s', using 1024\n",
              argv[1]);
    }
  }

  int rc = RunRank(my_rank, num_procs, threads_per_block);

  MPI_Finalize();
  return rc;
}
