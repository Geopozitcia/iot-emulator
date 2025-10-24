#ifndef TEMPERATURE_SENSOR_H
#define TEMPERATURE_SENSOR_H

#define TEMP_MIN 20.0
#define TEMP_MAX 35.0 // изменено в связи с частыми отключениями
#define SEND_DELAY_MS 500000
#define RETRY_DELAY 2
#define LOG_FILE "log/temperature_sensor.log"
#define SERVER_PORT 2229
#define BUFFER_SIZE 1024
#define BROADCAST_ADDR "255.255.255.255"

extern int is_enc;
extern int client_port; // Задается в реализации.

#endif