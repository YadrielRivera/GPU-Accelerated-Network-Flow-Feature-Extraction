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
       │ Load & batch (OpenMPI: whole files are split across ranks)
       ▼
[ Host Buffers ]
       │ Flat packet-byte buffer + one 32-byte metadata record per packet
       │ (offset, timestamp, captured length, wire length, source file id)
       ▼
[ Packet Parsing Kernel (CUDA) ]  one thread per packet
       │ Bounds-checked walk: Ethernet → VLAN / MPLS / PPPoE → IPv4 / IPv6 → TCP/UDP/SCTP
       │ Extract the flow key: (file id, Source IP, Dest IP, Source Port, Dest Port, Protocol)
       ▼
[ Parallel Hashing & Grouping ]
       │ FNV-1a + finalizer, linear probing, lock-free slot claim (atomicCAS)
       │ Accumulate packet/byte counts, min/max length, first/last timestamp (atomics)
       ▼
[ Flow Table (GPU Global Memory) ]
       │ Copy back to host, sanity checks, per-rank packet accounting
       ▼
[ Flow Records Output ]
```

## Pipeline Description

### Loading and Batching

The dataset directory is scanned for `.pcap` / `.cap` files, which are sorted alphabetically so that every MPI rank sees the same order. File *i* is loaded by rank `i % <number of ranks>`, so each rank independently reads its own subset of whole files.

Only classic pcap files with the Ethernet link type are loaded. Both byte orders and both timestamp resolutions (microsecond and nanosecond) are supported, and all timestamps are normalised to nanoseconds. Anything else (pcapng, gzip-compressed files, non-Ethernet link types such as Linux cooked or raw IP) is skipped with a message that states the reason. A cut-off final packet or a corrupt record length ends that file instead of being recorded.

Each rank stores its packets in two dynamically grown host buffers:
- a single flat byte buffer holding every packet's captured bytes, back to back;
- an array of 32-byte `pkt_info_t` records, one per packet, holding the byte offset into the flat buffer, the capture timestamp (ns), the captured length, the wire length, and a `file_id`.

The `file_id` is the file's index in the sorted list and is identical on every rank. Both buffers are then copied to the GPU in one transfer each.

### GPU Parsing - Extraction, Hashing, and Grouping

One thread handles one packet. The thread reads its `pkt_info_t` record and walks the headers, checking every read against the captured length so that truncated or malformed packets are counted instead of read out of bounds:

1. **Layer 2:** Ethernet, followed by any stack of 802.1Q / 802.1ad (QinQ) VLAN tags, an MPLS label stack, or a PPPoE session header carrying IPv4 or IPv6.
2. **Layer 3:** IPv4 (header length validated, non-first fragments detected) or IPv6 (the extension-header chain is walked, bounded, to find the real upper-layer protocol).
3. **Layer 4:** ports are read only for TCP, UDP and SCTP. For every other protocol (ICMP, IGMP, ...) and for non-first fragments the ports are 0, because those bytes are not ports.

Packets that carry no IP traffic (ARP, PPPoE discovery, any other EtherType) are counted as `non_flow`, and packets with truncated or invalid headers as `malformed`.

The flow key is:
- Capture file id
- Source IP (stored as a full 128 bits; IPv4 uses the first word)
- Destination IP
- Source port
- Destination port
- Network protocol (and IP version, so an IPv4 and an IPv6 address can never be mistaken for each other)

The file id is part of the key because the dataset consists of unrelated captures that reuse the same private address ranges. Without it, the same 5-tuple from two different files would merge into one flow.

Aggregation uses a variant of FNV-1a over the key words, followed by a murmur3 finalizer so that all key bits (for example the upper bits of the source port) influence the table index. The result indexes a one-dimensional flow table of 2^20 slots, and collisions are resolved with linear probing. Slots are claimed without locks: a thread `atomicCAS`es the slot from `EMPTY` to `WRITING`, writes the key, issues a memory fence and publishes `READY`. Other threads wait for `READY`, compare the key, and either update the record or probe to the next slot.

### GPU Feature Reduction and Computations

Each flow record holds the following, all accumulated by the parsing kernel with atomics at the moment a packet is matched to its flow:

| Field | Update |
|---|---|
| `packet_count` | `atomicAdd` |
| `byte_count` (wire length) | `atomicAdd` |
| `min_pkt_len` / `max_pkt_len` | `atomicMin` / `atomicMax` |
| `first_seen_ts` / `last_seen_ts` (ns) | `atomicMin` / `atomicMax` |

These aggregates do not depend on the order in which packets are processed, so no second pass or sorting is needed. Flow duration is `last_seen_ts - first_seen_ts`. A flow record is 88 bytes, so the table takes about 88 MiB of GPU memory.

Features that need per-flow packet order or a per-flow distribution (inter-arrival statistics, bursts, TCP flag counts, payload entropy) are not computed in this version.

Flows never span files, and each file is processed by exactly one rank, so each rank's flow table is complete and no cross-rank merging is needed.

After the kernel finishes, the table is copied back to the host and checked. Every packet falls into exactly one bucket, so each rank prints an accounting line that must balance:

```
[Rank 0] packets: total=4461 in_flows=3930 non_flow=531 malformed=0 table_full=0 -> all accounted for
```

`table_full` is non-zero only if the hash table runs out of slots, in which case a warning is printed. Records with a zero packet count, `min > max` or `first > last` are reported as failed sanity checks.

### CPU Loading & Batching

### CPU Parsing - Extraction, Hashing, and Grouping

### CPU Feature Reduction and Computations

## Requirements
* Linux-based OS
* OpenMPI (with the `mpicxx` compiler wrapper; MPI-3 is needed for per-node GPU selection)
* CUDA Toolkit (`nvcc`) and a CUDA-capable NVIDIA GPU with compute capability 7.0 or newer (Volta or later) (if running locally)
  * The slot-claiming code makes threads in the same warp wait on each other, which relies on independent thread scheduling. Compile for the target GPU's architecture (see the build command), not for an older default.
  * An alternative is to use the provided Google Colab file (details below)
* A host C++ compiler supported by your CUDA version (e.g. `g++`)
* git lfs - to pull PCAP data
* OpenMP (CPU baseline)
* CMake 3.28.3+ (to cleanly compile cpu baseline)
* The PCAP files placed in a `dataset` directory at the repository root. The path is hard-coded as `../../dataset`, relative to the directory the program is **run from**, so run it from `gpu/build` as shown below.

## File Structure
```bash
root
├── LICENSE
├── README.md
├── cpu
├── dataset/
└── gpu
    ├── include
    │   ├── pcap_batching.h
    │   └── pcap_parsing.h
    └── src
        ├── main.cu
        ├── pcap_batching.c
        └── pcap_parsing.cu
```

## Building, Compiling & Running (GPU)

### Locally
From the root directory
```bash
cd gpu
mkdir build 
cd build
nvcc -arch=native -ccbin mpicxx ../src/main.cu ../src/pcap_batching.c ../src/pcap_parsing.cu -o gpu
mpirun --allow-run-as-root --oversubscribe -np <mpi proc count> ./gpu <cuda threads>
```

`<cuda threads>` is the number of threads per block, between 1 and 1024 (default 1024). `-arch=native` targets the GPU in the build machine; if you build on a machine without the GPU, give the architecture explicitly instead (for example `-arch=sm_75` for a Colab T4). `--allow-run-as-root` and `--oversubscribe` are only needed in containers or when running more ranks than cores.

Each MPI rank is assigned to a GPU on its node (`rank % GPUs per node`). If there is more than one rank per GPU they share it, which works but gives no speedup.

### Google Colab

## Dataset
The PCAP data was obtained from WireShark [SampleCapture](https://wiki.wireshark.org/samplecaptures#sample-captures)

Files processed:
* Classic pcap files (`.pcap`, `.cap`), either byte order, microsecond or nanosecond timestamps
* Ethernet link type only

Files skipped, with the reason printed at load time (roughly a quarter of the Wireshark samples):
* pcapng files, and compressed files that only carry a `.pcap` name (convert with `editcap -F pcap in.pcapng out.pcap`, or decompress first)
* Any other link type (Linux cooked, raw IP, 802.11, Netlink, DVB-CI, ...)

Accepted ethernet types that produce flow records:
* IPv4
* IPv6
* VLAN_TAG (802.1Q and 802.1ad / QinQ, stacked)
* PPPoE_SESSION (carrying IPv4 or IPv6)
* MLPS_UNI
* MLPS_MULTI

Counted, but not tracked as flows (reported as `non_flow`):
* ARP
* PPPoE_DISCOV
* Any other EtherType

Note that timestamps are only comparable within one file: some captures use relative timestamps starting near zero, and others have wrong clocks. This is harmless for per-flow durations, since a flow never spans files, but flows from different files should not be ordered by timestamp.

## Building, Compiling & Running (CPU)

### Locally
From the root directory
```bash
cd cpu
mkdir build 
cd build
cmake -S .. -B .
make 
./cpu <number of omp threads>
```
