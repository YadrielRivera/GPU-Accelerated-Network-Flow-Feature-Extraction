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
       │ (Load & Batch via MPI4Py)
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

## Requirements
[To be determined]

## File Structure

## Building, Compiling & Running

## Data

## Useful Scripts

## A Note to the Reader
