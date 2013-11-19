/*
 * MAXIM DS1338 I2C RTC+NVRAM
 *
 * Copyright (c) 2009 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "i2c.h"

/* Size of NVRAM including both the user-accessible area and the
 * secondary register area.
 */
#define NVRAM_SIZE 64

typedef struct {
    I2CSlave i2c;
    int64_t offset;
    uint8_t nvram[NVRAM_SIZE];
    int32_t ptr;
    bool addr_byte;
} DS1338State;

static const VMStateDescription vmstate_ds1338 = {
    .name = "ds1338",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields = (VMStateField[]) {
        VMSTATE_I2C_SLAVE(i2c, DS1338State),
        VMSTATE_INT64(offset, DS1338State),
        VMSTATE_UINT8_ARRAY(nvram, DS1338State, NVRAM_SIZE),
        VMSTATE_INT32(ptr, DS1338State),
        VMSTATE_BOOL(addr_byte, DS1338State),
        VMSTATE_END_OF_LIST()
    }
};

static void capture_current_time(DS1338State *s)
{
    /* Capture the current time into the secondary registers
     * which will be actually read by the data transfer operation.
     */
    struct tm now;
    qemu_get_timedate(&now, s->offset);
    s->nvram[0] = to_bcd(now.tm_sec);
    s->nvram[1] = to_bcd(now.tm_min);
    if (s->nvram[2] & 0x40) {
        s->nvram[2] = (to_bcd((now.tm_hour % 12)) + 1) | 0x40;
        if (now.tm_hour >= 12) {
            s->nvram[2] |= 0x20;
        }
    } else {
        s->nvram[2] = to_bcd(now.tm_hour);
    }
    s->nvram[3] = to_bcd(now.tm_wday) + 1;
    s->nvram[4] = to_bcd(now.tm_mday);
    s->nvram[5] = to_bcd(now.tm_mon) + 1;
    s->nvram[6] = to_bcd(now.tm_year - 100);
}

static void inc_regptr(DS1338State *s)
{
    /* The register pointer wraps around after 0x3F; wraparound
     * causes the current time/date to be retransferred into
     * the secondary registers.
     */
    s->ptr = (s->ptr + 1) & (NVRAM_SIZE - 1);
    if (!s->ptr) {
        capture_current_time(s);
    }
}

static void ds1338_event(I2CSlave *i2c, enum i2c_event event)
{
    DS1338State *s = FROM_I2C_SLAVE(DS1338State, i2c);

    switch (event) {
    case I2C_START_RECV:
        /* In h/w, capture happens on any START condition, not just a
         * START_RECV, but there is no need to actually capture on
         * START_SEND, because the guest can't get at that data
         * without going through a START_RECV which would overwrite it.
         */
        capture_current_time(s);
        break;
    case I2C_START_SEND:
        s->addr_byte = true;
        break;
    default:
        break;
    }
}

static int ds1338_recv(I2CSlave *i2c)
{
    DS1338State *s = FROM_I2C_SLAVE(DS1338State, i2c);
    uint8_t res;

    res  = s->nvram[s->ptr];
    inc_regptr(s);
    return res;
}

static int ds1338_send(I2CSlave *i2c, uint8_t data)
{
    DS1338State *s = FROM_I2C_SLAVE(DS1338State, i2c);
    if (s->addr_byte) {
        s->ptr = data & (NVRAM_SIZE - 1);
        s->addr_byte = false;
        return 0;
    }
    if (s->ptr < 8) {
        struct tm now;
        qemu_get_timedate(&now, s->offset);
        switch(s->ptr) {
        case 0:
            /* TODO: Implement CH (stop) bit.  */
            now.tm_sec = from_bcd(data & 0x7f);
            break;
        case 1:
            now.tm_min = from_bcd(data & 0x7f);
            break;
        case 2:
            if (data & 0x40) {
                if (data & 0x20) {
                    data = from_bcd(data & 0x4f) + 11;
                } else {
                    data = from_bcd(data & 0x1f) - 1;
                }
            } else {
                data = from_bcd(data);
            }
            now.tm_hour = data;
            break;
        case 3:
            now.tm_wday = from_bcd(data & 7) - 1;
            break;
        case 4:
            now.tm_mday = from_bcd(data & 0x3f);
            break;
        case 5:
            now.tm_mon = from_bcd(data & 0x1f) - 1;
            break;
        case 6:
            now.tm_year = from_bcd(data) + 100;
            break;
        case 7:
            /* Control register. Currently ignored.  */
            break;
        }
        s->offset = qemu_timedate_diff(&now);
    } else {
        s->nvram[s->ptr] = data;
    }
    inc_regptr(s);
    return 0;
}

static int ds1338_init(I2CSlave *i2c)
{
    return 0;
}

static void ds1338_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *k = I2C_SLAVE_CLASS(klass);

    k->init = ds1338_init;
    k->event = ds1338_event;
    k->recv = ds1338_recv;
    k->send = ds1338_send;
    dc->vmsd = &vmstate_ds1338;
}

static TypeInfo ds1338_info = {
    .name          = "ds1338",
    .parent        = TYPE_I2C_SLAVE,
    .instance_size = sizeof(DS1338State),
    .class_init    = ds1338_class_init,
};

static void ds1338_register_types(void)
{
    type_register_static(&ds1338_info);
}

type_init(ds1338_register_types)
