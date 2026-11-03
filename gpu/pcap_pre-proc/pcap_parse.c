#include <dirent.h>
#include <mpi.h>
#include <stdint.h>
#include <stdio.h>

#include <string.h>


#define DATASET_PATH "../../../dataset"

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

// batches
uint8_t* packet_data = NULL;
int* packet_offsets = NULL;

size_t total_data_bytes = 0;
size_t total_packets = 0;
size_t data_capacity = 0;    // Current allocated capacity for bytes
size_t packet_capacity = 0;  // Current allocated capacity for offsets

int PcapRead(char pcap_file[]) {
  FILE* fd = fopen(pcap_file, "rb");

  if (fd == NULL) {
    printf("%s is an invalid pcap_file", pcap_file);
    perror("error opening pcap file: ");
    return 1;
  }

  pcap_hdr_t glob_hdr;
  int err = fread(&glob_hdr, sizeof(glob_hdr), 1, fd);

  if (err != 1) {
    perror("Error reading the pcap global header: ");
    return 1;
  }

  // unsupported pcaps, invalid magic numbers or big endian
  if (glob_hdr.magic_number != 0xa1b2c3d4 &&
      glob_hdr.magic_number != 0xa1b23c4d) {
    fclose(fd);
    return 1;
  }

  // check each packet header and write the data
  pcap_pkt_hdr_t pkt_hdr;
  while (fread(&pkt_hdr, sizeof(pkt_hdr), 1, fd) == 1) {
    int data_size = pkt_hdr.incl_len;

    // check if we need to resize our packet_offsets array
    if (total_packets >= packet_capacity) {
      packet_capacity = (packet_capacity == 0) ? 1024 : packet_capacity * 2;
      packet_offsets = (int*)realloc(packet_offsets, packet_capacity * sizeof(int));
    }

    // check if we need to resize our packet_data byte array
    if (total_data_bytes + data_size > data_capacity) {
      data_capacity = (data_capacity == 0) ? 65536 : data_capacity * 2;
      packet_data = (uint8_t*)realloc(packet_data, data_capacity * sizeof(uint8_t));
    }
    // record the starting offset for this packet
    packet_offsets[total_packets] = total_data_bytes;

    // read the entire packet payload directly into our flat buffer
    size_t bytes_read = fread(packet_data + total_data_bytes, 1, data_size, fd);
    if (bytes_read != data_size) {
      fprintf(stderr, "Warning: Expected %u bytes, but read %zu bytes.\n",
              data_size, bytes_read);
    }

    // Update our total byte tracker
    total_data_bytes += data_size;
    total_packets++;
  }

  fclose(fd);
}

int DatasetRead(int my_rank, int num_procs) {
  DIR* pcap_dir = opendir(DATASET_PATH);
  if (pcap_dir == NULL) {
    perror("Error opening dataset directory");
    return 1;
  }

  struct dirent* entry;
  char filepath[1024];
  int file_index = 0;

  while ((entry = readdir(pcap_dir)) != NULL) {
    if (entry->d_type != DT_REG) continue;
    if (strstr(entry->d_name, ".pcap") == NULL) continue;

    // Only process this file if it belongs to this MPI rank
    if (file_index % num_procs == my_rank) {
      snprintf(filepath, sizeof(filepath), "%s/%s", DATASET_PATH,
               entry->d_name);
      PcapRead(filepath);
    }

    file_index++;
  }

  closedir(pcap_dir);
  return 0;
}

int main(int argc, char* argv[]) {
  MPI_Init(&argc, &argv);

  int my_rank, num_procs;
  MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
  MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

  // Each rank parses its own subset of files into its local buffers
  DatasetRead(my_rank, num_procs);

  printf("[Rank %d] Finished loading. Total packets on this rank: %zu\n",
         my_rank, total_packets);

  MPI_Finalize();
  return 0;
}
