#include "pcap_batching.h"

#include <strings.h>
#include <sys/stat.h>

#define DATASET_PATH "../../dataset"

// Set to 0 to stop printing one line per loaded file.
#define LOG_EACH_FILE 1

// A single captured packet larger than this means a corrupt record.
#define MAX_PKT_BYTES (1u << 20)

uint8_t* packet_data = NULL;
pkt_info_t* packets = NULL;
size_t total_data_bytes = 0;
size_t total_packets = 0;
size_t data_capacity = 0;
size_t packet_capacity = 0;

static uint32_t Swap32(uint32_t v) { return __builtin_bswap32(v); }

// Grow both buffers geometrically. Returns 0 on success, -1 if out of memory.
static int EnsureCapacity(size_t need_packets, size_t need_bytes) {
  if (packets == NULL || need_packets > packet_capacity) {
    size_t cap = packet_capacity ? packet_capacity : 1024;
    while (cap < need_packets) cap *= 2;
    pkt_info_t* p = (pkt_info_t*)realloc(packets, cap * sizeof(pkt_info_t));
    if (p == NULL) return -1;
    packets = p;
    packet_capacity = cap;
  }
  if (packet_data == NULL || need_bytes > data_capacity) {
    size_t cap = data_capacity ? data_capacity : 65536;
    while (cap < need_bytes) cap *= 2;
    uint8_t* p = (uint8_t*)realloc(packet_data, cap);
    if (p == NULL) return -1;
    packet_data = p;
    data_capacity = cap;
  }
  return 0;
}

int PcapRead(const char* pcap_file, uint32_t file_id) {
  FILE* fd = fopen(pcap_file, "rb");
  if (fd == NULL) {
    fprintf(stderr, "Cannot open %s: ", pcap_file);
    perror(NULL);
    return 1;
  }

  pcap_hdr_t glob_hdr;
  if (fread(&glob_hdr, sizeof(glob_hdr), 1, fd) != 1) {
    fprintf(stderr, "%s: cannot read the pcap global header, skipped\n",
            pcap_file);
    fclose(fd);
    return 1;
  }

  // Classic pcap only. The magic tells us byte order and timestamp resolution.
  int swap = 0, nano = 0;
  switch (glob_hdr.magic_number) {
    case 0xa1b2c3d4:
      swap = 0;
      nano = 0;
      break;  // native, microseconds
    case 0xa1b23c4d:
      swap = 0;
      nano = 1;
      break;  // native, nanoseconds
    case 0xd4c3b2a1:
      swap = 1;
      nano = 0;
      break;  // swapped, microseconds
    case 0x4d3cb2a1:
      swap = 1;
      nano = 1;
      break;  // swapped, nanoseconds
    default:
      fprintf(stderr,
              "%s: unsupported format (magic 0x%08x, pcapng?), skipped\n",
              pcap_file, glob_hdr.magic_number);
      fclose(fd);
      return 1;
  }

  // The parser only understands Ethernet framing (linktype 1). The top 4 bits
  // of the field carry FCS info, so mask them off.
  uint32_t linktype =
      (swap ? Swap32(glob_hdr.network) : glob_hdr.network) & 0x0FFFFFFFu;
  if (linktype != 1) {
    fprintf(stderr, "%s: link type %u is not Ethernet, skipped\n", pcap_file,
            linktype);
    fclose(fd);
    return 1;
  }

  pcap_pkt_hdr_t pkt_hdr;
  while (fread(&pkt_hdr, sizeof(pkt_hdr), 1, fd) == 1) {
    uint32_t ts_sec = pkt_hdr.ts_sec;
    uint32_t ts_frac = pkt_hdr.ts_usec;
    uint32_t caplen = pkt_hdr.incl_len;
    uint32_t wirelen = pkt_hdr.orig_len;
    if (swap) {
      ts_sec = Swap32(ts_sec);
      ts_frac = Swap32(ts_frac);
      caplen = Swap32(caplen);
      wirelen = Swap32(wirelen);
    }

    if (caplen > MAX_PKT_BYTES) {
      fprintf(stderr,
              "%s: corrupt record (incl_len=%u), rest of file ignored\n",
              pcap_file, caplen);
      break;
    }

    if (EnsureCapacity(total_packets + 1, total_data_bytes + caplen) != 0) {
      fprintf(stderr, "Out of memory while loading %s\n", pcap_file);
      fclose(fd);
      return -1;
    }

    // Read the payload first; a cut-off last packet is dropped, not recorded.
    if (caplen > 0 &&
        fread(packet_data + total_data_bytes, 1, caplen, fd) != caplen) {
      fprintf(stderr, "%s: truncated final packet dropped\n", pcap_file);
      break;
    }

    pkt_info_t* p = &packets[total_packets];
    p->offset = total_data_bytes;
    p->ts_ns = (uint64_t)ts_sec * 1000000000ULL +
               (nano ? (uint64_t)ts_frac : (uint64_t)ts_frac * 1000ULL);
    p->caplen = caplen;
    p->wire_len = wirelen < caplen ? caplen : wirelen;  // guard bad orig_len
    p->file_id = file_id;
    p->_pad = 0;

    total_data_bytes += caplen;
    total_packets++;
  }

  fclose(fd);
  return 0;
}

static int HasSuffix(const char* s, const char* suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && strcasecmp(s + n - m, suffix) == 0;
}

int DatasetRead() {
  struct dirent** list = NULL;
  // scandir + alphasort gives every rank the same file order, so the
  // round-robin split below never skips or duplicates a file.
  int n = scandir(DATASET_PATH, &list, NULL, alphasort);
  if (n < 0) {
    perror("Error opening dataset directory");
    return 1;
  }

  char filepath[1024];
  uint32_t file_id = 0;  // counts candidate files, identical on every rank
  int loaded = 0, skipped = 0, rc = 0;

  for (int i = 0; i < n && rc == 0; i++) {
    const char* name = list[i]->d_name;
    if (!HasSuffix(name, ".pcap") && !HasSuffix(name, ".cap")) continue;

    int len = snprintf(filepath, sizeof(filepath), "%s/%s", DATASET_PATH, name);
    if (len < 0 || (size_t)len >= sizeof(filepath)) continue;

    // d_type can be DT_UNKNOWN on some filesystems, so ask stat() instead
    struct stat st;
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode)) continue;

    uint32_t this_id = file_id++;

    size_t before = total_packets;
    int r = PcapRead(filepath, this_id);
    if (r < 0) {
      rc = 1;
    } else if (r > 0) {
      skipped++;
    } else {
      loaded++;
#if LOG_EACH_FILE
      printf("file_id=%u %s (%zu packets)\n", this_id, name,
             total_packets - before);
#endif
    }
  }

  for (int i = 0; i < n; i++) free(list[i]);
  free(list);

  printf("files loaded: %d, skipped: %d\n", loaded, skipped);
  return rc;
}