#include <time.h>

#include "pcap_batching.h"
#include "pcap_processing.h"

// Helper function to format IPv4 and IPv6 addresses for printing
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

// ./cpu <number of OMP threads>
int main(int argc, char* argv[]) {
  int thread_count = 2;

  if (argc > 1) {
    int t = atoi(argv[1]);
    if (t >= 1) {
      thread_count = t;
    } else {
      fprintf(stderr, "Ignoring invalid thread count '%s', using 2\n", argv[1]);
    }
  }

  omp_set_num_threads(thread_count);
  printf("[CPU-OMP] Running with %d OpenMP threads\n", thread_count);

  struct timespec chron_s, chron_e;
  clock_gettime(CLOCK_MONOTONIC, &chron_s);

  // Read dataset files sequentially into flat host arrays
  if (DatasetRead() != 0) {
    fprintf(stderr, "Error reading dataset directory or pcap files.\n");
    return 1;
  }
  printf("Finished loading. Total packets loaded: %zu\n", total_packets);

  if (total_packets == 0) {
    printf("Nothing to process.\n");
    return 0;
  }

  // Allocate the global host-side flow table and stats structure
  const size_t table_bytes = sizeof(flow_record_t) * (size_t)HASH_TABLE_SIZE;
  flow_record_t* global_flow_table = (flow_record_t*)calloc(1, table_bytes);
  if (global_flow_table == NULL) {
    fprintf(stderr, "Out of host memory for the global flow table\n");
    free(packet_data);
    free(packets);
    return 1;
  }

  parse_stats_t stats = {0, 0, 0};

  // Execute the OpenMP parallel packet parsing and flow aggregation
  ProcessPacketsOpenMP(packet_data, packets, total_packets, global_flow_table,
                       &stats);

  // Post-process, validate, and print results
  size_t active_flows = 0;
  size_t packets_in_flows = 0;
  size_t bad_records = 0;

  for (size_t i = 0; i < (size_t)HASH_TABLE_SIZE; i++) {
    const flow_record_t* f = &global_flow_table[i];
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
          "flow file=%u %s:%u -> %s:%u proto=%u pkts=%u bytes=%llu"
          " len[min=%u max=%u] first=%llu last=%llu\n",
          f->key.file_id, src, f->key.src_port, dst, f->key.dst_port,
          f->key.proto, f->packet_count, (unsigned long long)f->byte_count,
          f->min_pkt_len, f->max_pkt_len, (unsigned long long)f->first_seen_ts,
          (unsigned long long)f->last_seen_ts);
    }
    packets_in_flows += f->packet_count;
    active_flows++;
  }

  size_t accounted =
      packets_in_flows + stats.non_flow + stats.malformed + stats.table_full;

  printf("Total unique flows detected: %zu\n", active_flows);
  printf(
      "packets: total=%zu in_flows=%zu non_flow=%llu malformed=%llu "
      "table_full=%llu -> %s\n",
      total_packets, packets_in_flows, stats.non_flow, stats.malformed,
      stats.table_full,
      accounted == total_packets ? "all accounted for" : "MISMATCH");

  if (stats.table_full > 0) {
    fprintf(stderr, "WARNING: flow table full, %llu packets were dropped\n",
            stats.table_full);
  }
  if (bad_records > 0) {
    fprintf(stderr, "WARNING: %zu flow records failed sanity checks\n",
            bad_records);
  }
  clock_gettime(CLOCK_MONOTONIC, &chron_e);

  int seconds = chron_e.tv_sec - chron_s.tv_sec;
  int nano = chron_e.tv_nsec - chron_s.tv_nsec;

  if (nano < 0) {
    seconds--;
    nano += 1000000000;
  }
  double delta = seconds + (nano / 1e9);

  printf("Took %.12f seconds to execute pipeline\n", delta);

  // Cleanup host memory allocations
  free(global_flow_table);
  free(packet_data);
  free(packets);

  return 0;
}