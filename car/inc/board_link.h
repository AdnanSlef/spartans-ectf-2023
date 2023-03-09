/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Function that defines interface for communication between boards
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#ifndef BOARD_LINK_H
#define BOARD_LINK_H

#include <stdint.h>

#include "inc/hw_memmap.h"
#include "firmware.h"
#include "uart.h"

#define UNLOCK_MAGIC 0x56
#define CHAL_START 0x57
#define RESP_START 0x58
#define FOB_UART ((uint32_t)UART1_BASE)

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void);

bool send_challenge(CHALLENGE *challenge);
bool fob_requests_unlock(void);
bool get_response(RESPONSE *response);

#endif
