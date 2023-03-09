/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Firmware UART interface implementation.
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "inc/hw_uart.h"
#include "inc/hw_nvic.h"
#include "driverlib/systick.h"

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "sb_all.h"

#include "board_link.h"
#include "uart.h"
#include "firmware.h"

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void) {
  SysCtlPeripheralEnable(SYSCTL_PERIPH_UART1);
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

  GPIOPinConfigure(GPIO_PB0_U1RX);
  GPIOPinConfigure(GPIO_PB1_U1TX);

  GPIOPinTypeUART(GPIO_PORTB_BASE, GPIO_PIN_0 | GPIO_PIN_1);

  // Configure the UART for 115,200, 8-N-1 operation.
  UARTConfigSetExpClk(
      FOB_UART, SysCtlClockGet(), 115200,
      (UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE));

  while (UARTCharsAvail(FOB_UART)) {
    UARTCharGet(FOB_UART);
  }
}

/**
 * @brief Function that determines whether the fob is requesting an unlock
 *
 * @return bool true if fob is requesting unlock, false otherwise
 */
bool fob_requests_unlock(void) {
  return uart_avail(FOB_UART) && uart_readb(FOB_UART)==UNLOCK_MAGIC;
}

/**
 * @brief Send a challenge-respones challenge to the secure fob device
*/
bool send_challenge(CHALLENGE *challenge) {
  uart_writeb(FOB_UART, CHAL_START);
  uart_write(FOB_UART, (uint8_t *)challenge, sizeof(CHALLENGE));
  return true;
}

/**
 * @brief Gets a response from the fob to the challenge that was sent
 * Times out after 1 second
 *
 * @param response [out] where to store the gathered response
 * @return bool true if response is received timely, false otherwise
 */
bool get_response(RESPONSE *response) {
  SysTickPeriodSet(16000000);
  HWREG(NVIC_ST_CURRENT) = 0; // Reset SysTick counter
  SysTickEnable();

  volatile uint32_t tick = SysTickValueGet();

  uint8_t * buffer = (uint8_t *) response;
  uint32_t buffer_length = sizeof(RESPONSE);
  uint32_t i = 0;

  bool success = false;
  bool started = false;

  // while (tick > 1000) {
  while (true) {//TODO enable timeout
    if (UARTCharsAvail(FOB_UART) && i < buffer_length) {
      if(started) {
        buffer[i] = UARTCharGetNonBlocking(FOB_UART);
        i++;

        if (i == buffer_length) {
          success = true;
          break;
        }
      }
      else if (UARTCharGetNonBlocking(FOB_UART) == RESP_START) {
        started = true;
      }
    }

    tick = SysTickValueGet();
  }

  SysTickDisable();

  return success;
}
