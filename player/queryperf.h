#ifndef QUERYPERF_H
#define QUERYPERF_H

#define MAX_QNAME_SZ 512

#define nptohs(p) \
   ((((uint8_t*)(p))[0] << 8) | ((uint8_t*)(p))[1])

#endif
