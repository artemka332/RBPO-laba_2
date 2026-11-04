#include "telemetry_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define RECV_BUFFER_SIZE 256

int main(int argc, char* argv[])
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char net_buffer[RECV_BUFFER_SIZE];

    printf("[НКУ] Сервер телеметрии запущен (TCP-порт: %d)\n", TELEMETRY_TCP_PORT);
    telemetry_init_channels();

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TELEMETRY_TCP_PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0)
    {
        perror("listen failed");
        close(server_fd);
        return 1;
    }

    // Режим --dry-run для безопасного дымового тестирования в CI/CD без зависания
    if (argc > 1 && strcmp(argv[1], "test") == 0)
    {
        printf("[CI/CD] Smoke test успешен. Завершение работы.\n");
        close(server_fd);
        return 0;
    }

    while (1) 
    {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;

        ssize_t bytes_read = recv(client_fd, net_buffer, sizeof(net_buffer) - 1, 0);
        if (bytes_read > 0)
        {
            net_buffer[bytes_read] = '\0';
            TelemetryFrame frame;
            if (telemetry_parse_frame(net_buffer, &frame) == 0)
            {
                telemetry_dispatch_frame(&frame);
                send(client_fd, "ACK\n", 4, 0);
            }
            
            else
            {
                send(client_fd, "NACK\n", 5, 0);
            }
        }
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
