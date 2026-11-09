#include "pcap_batching.h"

// ./cpu <number of OMP threads>
int main(int argc, char* argv[]) {
  int thread_count = 2;

  if (argc > 1) {
    thread_count = atoi(argv[1]);
  }

  omp_set_num_threads(thread_count);

  // call the batching method/s
  DatasetRead();

  // call the processing methods

  // output the result

  return 0;
}