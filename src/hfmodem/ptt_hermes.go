// NNCP -- Node to Node copy, utilities for store-and-forward data exchange
// Copyright (C) 2016-2026 Sergey Matveev <stargrave@stargrave.org>
// Copyright (C) 2026 Rhizomatica <rafael@rhizomatica.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//go:build !nohfmodem && linux

package hfmodem

/*
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SYSV_SHM_CONTROLLER_KEY_STR 66650
#define MAX_MESSAGE_SIZE 128

typedef struct {
    uint8_t service_command[5];
    pthread_mutex_t cmd_mutex;
    pthread_cond_t cmd_condition;

    pthread_mutex_t response_mutex;

    uint8_t response_service[5];
    atomic_bool response_available;

    int radio_fd;

    char message[MAX_MESSAGE_SIZE];
    atomic_bool message_available;
} controller_conn;

static bool radio_cmd(controller_conn *connector, uint8_t *srv_cmd, uint8_t *response)
{
    bool ret_value = false;

    pthread_mutex_lock(&connector->response_mutex);
    pthread_mutex_lock(&connector->cmd_mutex);

    memcpy(connector->service_command, srv_cmd, 5);
    connector->response_available = false;

    pthread_cond_signal(&connector->cmd_condition);
    pthread_mutex_unlock(&connector->cmd_mutex);

    // ~3 ms max wait
    uint32_t tries = 0;
    uint32_t sleep_time = 100;
    while (connector->response_available == false && tries < 30)
    {
        usleep(sleep_time);
        tries++;
        if (!(tries % 4))
            sleep_time <<= 1;
    }

    if (connector->response_available == true)
    {
        memcpy(response, connector->response_service, 5);
        connector->response_available = false;
        ret_value = true;
    }

    pthread_mutex_unlock(&connector->response_mutex);
    return ret_value;
}

static controller_conn* shm_attach_controller()
{
    int shmid = shmget(SYSV_SHM_CONTROLLER_KEY_STR, sizeof(controller_conn), 0);
    if (shmid == -1)
        return NULL;
    return (controller_conn *)shmat(shmid, NULL, 0);
}

// Command codes from radio_cmds.h
#define CMD_PTT_ON  0x10
#define CMD_PTT_OFF 0x11
#define CMD_SET_CONNECTED_STATUS 0x15
#define CMD_SET_BITRATE 0x32
#define CMD_SET_SNR     0x34
#define CMD_SET_BYTES_RX 0x36
#define CMD_SET_BYTES_TX 0x38

static bool hermes_ptt_on(controller_conn *conn) {
    uint8_t cmd[5] = {0, 0, 0, 0, CMD_PTT_ON};
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}

static bool hermes_ptt_off(controller_conn *conn) {
    uint8_t cmd[5] = {0, 0, 0, 0, CMD_PTT_OFF};
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}

static bool hermes_set_connected(controller_conn *conn, uint8_t status) {
    uint8_t cmd[5] = {status, 0, 0, 0, CMD_SET_CONNECTED_STATUS};
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}

static bool hermes_set_bitrate(controller_conn *conn, uint32_t bitrate) {
    uint8_t cmd[5];
    memcpy(cmd, &bitrate, 4);
    cmd[4] = CMD_SET_BITRATE;
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}

static bool hermes_set_snr(controller_conn *conn, int32_t snr) {
    uint8_t cmd[5];
    memcpy(cmd, &snr, 4);
    cmd[4] = CMD_SET_SNR;
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}

static bool hermes_set_bytes_rx(controller_conn *conn, int32_t bytes) {
    uint8_t cmd[5];
    memcpy(cmd, &bytes, 4);
    cmd[4] = CMD_SET_BYTES_RX;
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}

static bool hermes_set_bytes_tx(controller_conn *conn, int32_t bytes) {
    uint8_t cmd[5];
    memcpy(cmd, &bytes, 4);
    cmd[4] = CMD_SET_BYTES_TX;
    uint8_t resp[5];
    return radio_cmd(conn, cmd, resp);
}
*/
import "C"

import (
	"fmt"
	"log"
	"unsafe"
)

// hermesKeyer controls PTT and sends status updates via the Hermes
// sBitx radio controller's SysV shared memory interface (key 66650).
type hermesKeyer struct {
	conn *C.controller_conn
}

func newHermesKeyer(_ string) (*hermesKeyer, error) {
	conn := C.shm_attach_controller()
	if conn == nil {
		return nil, fmt.Errorf("hermes: cannot attach to radio controller SHM (key %d)", 66650)
	}
	return &hermesKeyer{conn: conn}, nil
}

func (k *hermesKeyer) KeyOn() error {
	if !C.hermes_ptt_on(k.conn) {
		log.Printf("hfmodem: hermes PTT ON: no response from radio controller")
	}
	return nil
}

func (k *hermesKeyer) KeyOff() error {
	if !C.hermes_ptt_off(k.conn) {
		log.Printf("hfmodem: hermes PTT OFF: no response from radio controller")
	}
	return nil
}

func (k *hermesKeyer) Close() error {
	// Set disconnected status and clear stats
	C.hermes_set_connected(k.conn, 0)
	C.hermes_set_bitrate(k.conn, 0)
	C.hermes_set_snr(k.conn, 0)
	// Detach SHM
	C.shmdt(unsafe.Pointer(k.conn))
	k.conn = nil
	return nil
}

func (k *hermesKeyer) SetConnected(connected bool) {
	var status C.uint8_t
	if connected {
		status = 1
	}
	C.hermes_set_connected(k.conn, status)
}

func (k *hermesKeyer) SetBitrate(bitrate uint32) {
	C.hermes_set_bitrate(k.conn, C.uint32_t(bitrate))
}

func (k *hermesKeyer) SetSNR(snr int32) {
	C.hermes_set_snr(k.conn, C.int32_t(snr))
}

func (k *hermesKeyer) SetBytesRx(bytes int32) {
	C.hermes_set_bytes_rx(k.conn, C.int32_t(bytes))
}

func (k *hermesKeyer) SetBytesTx(bytes int32) {
	C.hermes_set_bytes_tx(k.conn, C.int32_t(bytes))
}
