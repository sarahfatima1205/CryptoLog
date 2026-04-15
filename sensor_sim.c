/*
 * sensor_sim.c — Simulated sensor data
 *
 * Generates realistic-looking temperature, pressure, humidity
 * with slow drift and small noise. Replace sensor_read() body
 * with real I2C/SPI reads when you get hardware.
 */

#include "sensor_sim.h"
#include "stm32f4xx_hal.h"

static uint32_t tick = 0;

SensorData sensor_read(void) {
    tick++;
    SensorData d;

    /*
     * Temperature: 20.00°C base, slow sine-ish drift, small noise
     * Using integer arithmetic only — no floats on embedded
     */
    uint32_t drift   = (tick * 7) % 1500;   /* 0..14.99°C range */
    uint32_t noise   = (tick * 31 + DWT->CYCCNT) % 50;  /* ±0.25°C */
    d.temperature    = 2000 + drift + noise;

    /* Pressure: 101000..102000 Pa */
    d.pressure       = 101000 + ((tick * 13) % 1000);

    /* Humidity: 45.00% .. 75.00% */
    d.humidity       = 4500 + ((tick * 11) % 3000);

    /* Timestamp: simulated 5-second intervals */
    d.timestamp      = tick * 5;

    return d;
}
