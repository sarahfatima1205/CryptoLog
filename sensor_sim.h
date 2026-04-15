/* ---------------------------------------------------------
 * sensor_sim.h
 * --------------------------------------------------------- */
#ifndef SENSOR_SIM_H
#define SENSOR_SIM_H
#include <stdint.h>

typedef struct {
    uint32_t temperature;  /* 0.01 °C  e.g. 2547 = 25.47°C */
    uint32_t pressure;     /* Pa       e.g. 101325          */
    uint32_t humidity;     /* 0.01 %   e.g. 6000 = 60.00%  */
    uint32_t timestamp;    /* simulated seconds since boot  */
} SensorData;

SensorData sensor_read(void);

#endif
