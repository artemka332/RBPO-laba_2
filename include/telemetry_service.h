#ifndef TELEMETRY_SERVICE_H
#define TELEMETRY_SERVICE_H

#include <stdint.h>
#include <stdbool.h>

#define TELEMETRY_TCP_PORT 5005
#define MAX_SUBSYS_LEN     16
#define CHANNEL_COUNT      4

typedef struct
{
    uint32_t frame_seq;
    uint8_t  spw_logical_addr;
    char     subsystem_tag[MAX_SUBSYS_LEN];
    float    measurement;
} TelemetryFrame;

typedef struct
{
    char     subsystem_tag[MAX_SUBSYS_LEN];
    uint32_t total_frames;
    float    last_measurement;
    bool     is_active;
} TelemetryChannel;

void telemetry_init_channels(void);
TelemetryChannel* telemetry_find_channel(const char* tag);
int  telemetry_parse_frame(const char* raw_packet, TelemetryFrame* out_frame);
void telemetry_dispatch_frame(const TelemetryFrame* frame);

#endif
