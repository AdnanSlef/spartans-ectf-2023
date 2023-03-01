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

#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

#include "board_link.h"

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
 * @brief Send a message between boards
 *
 * @param message pointer to message to send
 * @return uint32_t the number of bytes sent
 */
uint32_t send_board_message(MESSAGE_PACKET *message) {//TODO delete, just a model for send
  UARTCharPut(FOB_UART, message->magic);
  UARTCharPut(FOB_UART, message->message_len);

  for (int i = 0; i < message->message_len; i++) {
    UARTCharPut(FOB_UART, message->buffer[i]);
  }

  return message->message_len;
}

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t receive_board_message(MESSAGE_PACKET *message) { //TODO delete or adapt, just a model for receive
  message->magic = (uint8_t)UARTCharGet(FOB_UART);

  if (message->magic == 0) {
    return 0;
  }

  message->message_len = (uint8_t)UARTCharGet(FOB_UART);

  for (int i = 0; i < message->message_len; i++) {
    message->buffer[i] = (uint8_t)UARTCharGet(FOB_UART);
  }

  return message->message_len;
}


/**
 * @brief Function that determines whether the fob is requesting an unlock
 *
 * @return bool true if fob is requesting unlock, false otherwise
 */
bool fob_requests_unlock() {
  return uart_avail(FOB_UART) && uart_readb(FOB_UART)==UNLOCK_MAGIC;
}

/**
 * @brief Gets a response from the fob to the challenge that was sent
 * Times out after 1 second of 
 *
 * @param response [out] where to store the gathered response
 * @return bool true if fob is requesting unlock, false otherwise
 */
bool get_response(RESPONSE *response) {
  //read a defined number of bytes, but only for 1 second
  //TODO timeout after 1 second, returning false

}