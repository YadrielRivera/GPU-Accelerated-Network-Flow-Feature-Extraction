#include "../include/pcap_parsing.h"
#include "../include/pcap_batching.h"

__device__ __forceinline__ uint16_t be16(const uint8_t* p) {
  return ((uint16_t)p[0] << 8) | p[1];
}

__device__ __forceinline__ uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

__device__ __forceinline__ uint32_t Mix(uint32_t h, uint32_t x) {
  h ^= x;
  return h * 16777619u;  // FNV prime
}

__device__ uint32_t HashKey(const flow_key_t& k) {
  uint32_t h = 2166136261u;  // FNV offset basis
  h = Mix(h, k.file_id);
#pragma unroll
  for (int i = 0; i < 4; i++) h = Mix(h, k.src_ip[i]);
#pragma unroll
  for (int i = 0; i < 4; i++) h = Mix(h, k.dst_ip[i]);
  h = Mix(h, ((uint32_t)k.src_port << 16) | k.dst_port);
  h = Mix(h, ((uint32_t)k.proto << 8) | k.ip_ver);
  // murmur3 finalizer: a multiply only carries information upward, so without
  // this the bits kept by HASH_MASK ignore most of the high input bits (e.g.
  // the upper bits of the source port).
  h ^= h >> 16;
  h *= 0x85ebca6bu;
  h ^= h >> 13;
  h *= 0xc2b2ae35u;
  h ^= h >> 16;
  return h;
}

__device__ __forceinline__ void StoreKey(volatile flow_key_t* d,
                                         const flow_key_t& k) {
  d->file_id = k.file_id;
#pragma unroll
  for (int i = 0; i < 4; i++) {
    d->src_ip[i] = k.src_ip[i];
    d->dst_ip[i] = k.dst_ip[i];
  }
  d->src_port = k.src_port;
  d->dst_port = k.dst_port;
  d->proto = k.proto;
  d->ip_ver = k.ip_ver;
}

__device__ __forceinline__ void LoadKey(const volatile flow_key_t* s,
                                        flow_key_t* k) {
  k->file_id = s->file_id;
#pragma unroll
  for (int i = 0; i < 4; i++) {
    k->src_ip[i] = s->src_ip[i];
    k->dst_ip[i] = s->dst_ip[i];
  }
  k->src_port = s->src_port;
  k->dst_port = s->dst_port;
  k->proto = s->proto;
  k->ip_ver = s->ip_ver;
}

__device__ __forceinline__ bool KeyEq(const flow_key_t& a,
                                      const flow_key_t& b) {
  if (a.file_id != b.file_id || a.src_port != b.src_port ||
      a.dst_port != b.dst_port || a.proto != b.proto || a.ip_ver != b.ip_ver)
    return false;
#pragma unroll
  for (int i = 0; i < 4; i++) {
    if (a.src_ip[i] != b.src_ip[i] || a.dst_ip[i] != b.dst_ip[i]) return false;
  }
  return true;
}

__device__ bool AggregateFlow(flow_record_t* table, const flow_key_t& key,
                              uint32_t pkt_len, uint64_t ts) {
  uint32_t idx = HashKey(key) & HASH_MASK;

  for (uint32_t probes = 0; probes < HASH_TABLE_SIZE; probes++) {
    flow_record_t* slot = &table[idx];
    volatile flow_record_t* vslot = slot;

    // Try to claim an empty slot
    uint32_t prev = atomicCAS(&slot->state, SLOT_EMPTY, SLOT_WRITING);

    if (prev == SLOT_EMPTY) {
      // We own it: write the key, then publish
      StoreKey(&vslot->key, key);
      // table is zero-initialised; min/first need a "maximum" starting value
      vslot->min_pkt_len = UINT32_MAX;
      vslot->first_seen_ts = UINT64_MAX;
      __threadfence();  // key visible before READY
      atomicExch(&slot->state, SLOT_READY);
    } else {
      // Someone else owns it: wait until their key is fully published
      while (vslot->state != SLOT_READY) {
      }
      __threadfence();
    }

    // Slot is READY: does the key match?
    flow_key_t cur;
    LoadKey(&vslot->key, &cur);
    if (KeyEq(cur, key)) {
      atomicAdd(&slot->packet_count, 1);
      atomicAdd((unsigned long long*)&slot->byte_count,
                (unsigned long long)pkt_len);
      atomicMin(&slot->min_pkt_len, pkt_len);
      atomicMax(&slot->max_pkt_len, pkt_len);
      atomicMin((unsigned long long*)&slot->first_seen_ts,
                (unsigned long long)ts);
      atomicMax((unsigned long long*)&slot->last_seen_ts,
                (unsigned long long)ts);
      return true;
    }
    idx = (idx + 1) & HASH_MASK;  // genuinely different flow: probe on
  }
  return false;  // table full
}

__device__ bool ParseIP(const uint8_t* pkt, uint32_t caplen, const uint8_t* l3,
                        flow_key_t* key) {
  const uint8_t* end = pkt + caplen;
  if (l3 >= end) return false;

  uint8_t version = l3[0] >> 4;
  const uint8_t* l4;
  bool ports_ok = true;  // false for non-first fragments: no L4 header there
  uint8_t proto;

  if (version == 4) {
    if (end - l3 < 20) return false;
    uint32_t ihl = (uint32_t)(l3[0] & 0x0F) * 4;
    if (ihl < 20 || (uint32_t)(end - l3) < ihl) return false;

    key->ip_ver = 4;
    key->src_ip[0] = be32(l3 + 12);
    key->dst_ip[0] = be32(l3 + 16);
    for (int i = 1; i < 4; i++) key->src_ip[i] = key->dst_ip[i] = 0;
    proto = l3[9];
    ports_ok = (be16(l3 + 6) & 0x1FFF) == 0;  // fragment offset
    l4 = l3 + ihl;
  } else if (version == 6) {
    if (end - l3 < 40) return false;

    key->ip_ver = 6;
    for (int i = 0; i < 4; i++) {
      key->src_ip[i] = be32(l3 + 8 + 4 * i);
      key->dst_ip[i] = be32(l3 + 24 + 4 * i);
    }

    // Walk the extension header chain (bounded) to find the real protocol.
    uint8_t nh = l3[6];
    const uint8_t* cur = l3 + 40;
    for (int n = 0; n < 8; n++) {
      uint32_t hlen;
      if (nh == 0 || nh == 43 || nh == 60) {  // hop-by-hop, routing, dest opts
        if (end - cur < 8) return false;
        hlen = ((uint32_t)cur[1] + 1) * 8;
      } else if (nh == 51) {  // authentication header
        if (end - cur < 8) return false;
        hlen = ((uint32_t)cur[1] + 2) * 4;
      } else if (nh == 44) {  // fragment header
        if (end - cur < 8) return false;
        if ((be16(cur + 2) >> 3) != 0) ports_ok = false;
        hlen = 8;
      } else {
        break;
      }
      if ((uint32_t)(end - cur) < hlen) return false;
      nh = cur[0];
      cur += hlen;
    }
    proto = nh;
    l4 = cur;
  } else {
    return false;
  }

  key->proto = proto;
  key->src_port = 0;
  key->dst_port = 0;
  // Only TCP/UDP/SCTP have ports. For ICMP & co. the bytes there are type /
  // checksum, which would split one logical flow into many.
  if (ports_ok && (proto == TCP || proto == UDP || proto == SCTP) &&
      end - l4 >= 4) {
    key->src_port = be16(l4);
    key->dst_port = be16(l4 + 2);
  }
  return true;
}

__global__ void PcapParallelParsing(const uint8_t* d_packet_data,
                                    const pkt_info_t* d_packets,
                                    size_t d_total_packets,
                                    flow_record_t* d_flow_table,
                                    parse_stats_t* d_stats) {
  size_t th_idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
  if (th_idx >= d_total_packets) return;

  const pkt_info_t info = d_packets[th_idx];
  const uint8_t* pkt = d_packet_data + info.offset;
  const uint8_t* end = pkt + info.caplen;

  if (info.caplen < 14) {
    atomicAdd(&d_stats->malformed, 1ULL);
    return;
  }

  uint16_t ethertype = be16(pkt + 12);
  const uint8_t* cur = pkt + 14;
  bool malformed = false;

  // VLAN tags (802.1Q / 802.1ad), possibly stacked
  for (int d = 0; d < 8 && (ethertype == VLAN_TAG || ethertype == QINQ_TAG);
       d++) {
    if (end - cur < 4) {
      malformed = true;
      break;
    }
    ethertype = be16(cur + 2);
    cur += 4;
  }

  const uint8_t* l3 = NULL;
  if (!malformed) {
    switch (ethertype) {
      case IPv4:
      case IPv6:
        l3 = cur;
        break;
      case MLPS_UNI:
      case MLPS_MULTI: {
        // pop labels until the bottom-of-stack bit (bounded)
        bool bos = false;
        for (int d = 0; d < 16 && !bos; d++) {
          if (end - cur < 4) {
            malformed = true;
            break;
          }
          bos = (cur[2] & 0x01) != 0;
          cur += 4;
        }
        if (!malformed) {
          if (!bos) {
            malformed = true;
          } else if (end - cur >= 1 &&
                     ((cur[0] >> 4) == 4 || (cur[0] >> 4) == 6)) {
            l3 = cur;
          }
        }
        break;
      }
      case PPPoE_SESSION: {
        // 6-byte PPPoE header + 2-byte PPP protocol: 0x0021 = IPv4, 0x0057 = IPv6
        if (end - cur < 8) {
          malformed = true;
          break;
        }
        uint16_t ppp = be16(cur + 6);
        if (ppp == 0x0021 || ppp == 0x0057) l3 = cur + 8;
        break;
      }
      default:  // ARP, PPPoE discovery, anything else: no flow
        break;
    }
  }

  if (malformed) {
    atomicAdd(&d_stats->malformed, 1ULL);
    return;
  }
  if (l3 == NULL) {
    atomicAdd(&d_stats->non_flow, 1ULL);
    return;
  }

  flow_key_t key;
  key.file_id = info.file_id;
  if (!ParseIP(pkt, info.caplen, l3, &key)) {
    atomicAdd(&d_stats->malformed, 1ULL);
    return;
  }

  // Length = frame length on the wire (pcap orig_len), independent of the IP
  // header, so TSO/GSO captures (IP total length 0) and padding are handled.
  if (!AggregateFlow(d_flow_table, key, info.wire_len, info.ts_ns)) {
    atomicAdd(&d_stats->table_full, 1ULL);
  }
}
