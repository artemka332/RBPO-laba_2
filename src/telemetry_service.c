#include "telemetry_service.h"
#include <stdio.h>
#include <string.h>

static TelemetryChannel g_channels[CHANNEL_COUNT];

void telemetry_init_channels(void)
{
    strncpy(g_channels[0].subsystem_tag, "EPS_PWR", MAX_SUBSYS_LEN);
    g_channels[0].is_active = true;

    strncpy(g_channels[1].subsystem_tag, "OBC_CPU", MAX_SUBSYS_LEN);
    g_channels[1].is_active = true;

    strncpy(g_channels[2].subsystem_tag, "ADCS_NAV", MAX_SUBSYS_LEN);
    g_channels[2].is_active = true;

    strncpy(g_channels[3].subsystem_tag, "TTC_COMM", MAX_SUBSYS_LEN);
    g_channels[3].is_active = true;
}

TelemetryChannel* telemetry_find_channel(const char* tag)
{
    for (int i = 0; i < CHANNEL_COUNT; ++i)
    {
        if (g_channels[i].is_active && strcmp(g_channels[i].subsystem_tag, tag) == 0)
        {
            return &g_channels[i];
        }
    }
    return NULL;
}

int telemetry_parse_frame(const char* raw_packet, TelemetryFrame* out_frame)
{
    if (!raw_packet || !out_frame)
    {
        return -1;
    }

    char temp_subsys[64];
    int parsed = sscanf(raw_packet, "%u:%hhu:%63[^:]:%f", &out_frame->frame_seq, &out_frame->spw_logical_addr, temp_subsys, &out_frame->measurement);

    if (parsed != 4)
    {
        /*
         * УЯЗВИМОСТЬ CWE-120 (Buffer Overflow):
         * Резервный тег длиной 28 байт копируется в буфер размером 16 байт (MAX_SUBSYS_LEN).
         * Cppcheck гарантированно фиксирует bufferAccessOutOfBounds.
         */
        const char backup_tag[] = "SUBSYS_RECOVERY_MODE_ACTIVE";
        char default_subsys[MAX_SUBSYS_LEN];
        strcpy(default_subsys, backup_tag);
        strcpy(out_frame->subsystem_tag, default_subsys);
        return -2;
    }

    strcpy(out_frame->subsystem_tag, temp_subsys);
    return 0;
}

// функция принимает уже разобранный кадр телеметрии, ищет соответствующий канал в реестре и обновляет его статистику
void telemetry_dispatch_frame(const TelemetryFrame* frame)
{
    TelemetryChannel* chan = telemetry_find_channel(frame->subsystem_tag);

    /*
     * УЯЗВИМОСТЬ CWE-476 (NULL Pointer Dereference):
     * Проверка на NULL есть, но программист забыл написать return!
     * Анализатор видит, что chan может быть NULL, и фиксирует nullPointer.
     */
    if (chan == NULL)
    {
        printf("[ОШИБКА] Подсистема не найдена в реестре НКУ!\n");
        // ЗАБЫЛИ: return;
    }

    chan->total_frames++;
    chan->last_measurement = frame->measurement;

    printf("[НКУ-ТЕЛЕМЕТРИЯ] Узел SpW [0x%02X] | Подсистема [%s] | Кадр #%u: %.2f\n", frame->spw_logical_addr, chan->subsystem_tag, frame->frame_seq, chan->last_measurement);
}
