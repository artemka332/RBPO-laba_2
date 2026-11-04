cmake_minimum_required(VERSION 3.16)
project(nku_telemetry_tcp C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Строгие флаги компилятора
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O0 -g")

include_directories(include)

add_executable(telemetry_server
    src/main.c
    src/telemetry_service.c
)
