# GPU-Accelerated-Network-Flow-Feature-Extraction

## Proposal
**Area**: Cybersecurity / Data Processing
1. **Problem Statement**
Raw packet captures contain enormous numbers of packets. Computing flow-level features—
packet counts, byte counts, inter-arrival statistics, flags, entropy, burst characteristics—
requires grouping and aggregation, which can be expensive at scale.
2. **Potential Solution**
Design a packet-to-flow feature-extraction pipeline. Use parallel hashing/grouping and
reduction to construct flow records, then calculate statistical features. The challenging
component is contention and irregular memory access when many packets belong to the same
flow. Compare CPU threading with GPU approaches and investigate skewed traffic
distributions.
3. **Tools / Parallelization Strategy**
CUDA for packet/feature kernels; OpenMP for CPU baseline; MPI4Py for distributed PCAP
batches.

## Pipeline Anatomy
```
[ Raw PCAP Files ] 
       │ (Load & Batch via OpenMPI)
       ▼
[ Packet Parsing Kernel (CUDA) ] 
       │ Extract 5-tuple: (Source IP, Dest IP, Source Port, Dest Port, Protocol)
       ▼
[ Parallel Hashing & Grouping ] 
       │ Resolve collisions & accumulate counts/bytes in GPU Global Memory
       ▼
[ Feature Reduction & Computation ] 
       │ Calculate inter-arrival times, entropy, and flags
       ▼
[ Flow Records Output ]
```

## Pipeline Description

### Loading and Batching

Raw PCAP files from the dataset directory are read and processed. They are stored in a dynamically allocated, uni-dimensional buffer that contains packet headers + payloads. Additionally, a second buffer stores the packet offsets; these indicate the GPU threads which index corresponds to the packet to work on.

### GPU Parsing - Extraction, Hashing, and Grouping
Each thread calculates it global buffer index to work on the corresponding packet. After extracting the ethernet type
the threads determine how to extract payloads for each of the types and aggregate a 5-tuple into a flow record. The 5-tuple contains:
- Source IP
- Destination IP
- Source port
- Destination port
- Network protocol

Aggregation is executed via a variant FNV-1a hashing into a uni-dimensional flow table. The collision handling approach is Linear Probing.

### Feature Reduction and Computations

## Requirements
* Linux-based OS
* OpenMPI 
* git lfs - to pull PCAP data
* CUDA and a CUDA-capable GPU (if running locally)
  * An alternative is to use the provided Google Colab file (details below)
* OpenMP


## File Structure

## Building, Compiling & Running (GPU)

### Locally
From the root directory
```bash
cd gpu
mkdir build 
cd build
nvcc -ccbin mpicxx ../src/main.cu ../src/pcap_batching.c ../src/pcap_parsing.cu -o gpu
mpirun --allow-run-as-root --oversubscribe -np <mpi proc count> ./gpu <cuda threads>
```


### Google Colab

## Dataset
The PCAP data was obtained from WireShark [SampleCapture](https://wiki.wireshark.org/samplecaptures#sample-captures)

Accepted and processed ethernet types:
* IPv4
* ARP 
* IPv6 
* VLAN_TAG 
* PPPoE_DISCOV
* PPPoE_SESSION 
* MLPS_UNI 
* MLPS_MULTI 

## Useful Scripts
