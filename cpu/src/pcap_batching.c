#include "pcap_batching.h"

uint8_t* packet_data = NULL;
pkt_info_t* packets = NULL;
size_t total_data_bytes = 0;
size_t total_packets = 0;
size_t data_capacity = 0;
size_t packet_capacity = 0;

int PcapRead(const char* pcap_file, uint32_t file_id) {}

int DatasetRead(int num_threads) {}