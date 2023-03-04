/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Car Example Design Implementation
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
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "secrets.h"

#include "sb_all.h"

#include "board_link.h"
#include "uart.h"
#include "firmware.h"

/*** Macros ***/
#define ZERO(M) memset(&M, 0, sizeof(M))

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {
  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  while (true) {

    tryUnlock();
  }
}

/**
 * @brief Function that handles unlocking of car
 */
void tryUnlock(void) {
  CHALLENGE challenge;
  RESPONSE response;

  // Clear response
  ZERO(response);

  // Make sure the fob is requesting an unlock
  fob_requests_unlock() &&

  // Generate a challenge
  gen_challenge(&challenge) &&

  // Send challenge to fob
  send_challenge(&challenge) &&

  // Get response within 1 second
  get_response(&response) &&

  // Check whether the response to the challenge was valid
  verify_response(&challenge, &response) &&
  
  // Unlock the car
  unlockCar() &&

  // Start the car
  startCar(&reponse);
}

bool gen_challenge(CHALLENGE *challenge) {
  return false;
}

bool verify_response(CHALLENGE *challenge, RESPONSE *response) {
  //verify the challenge-response response
  //verify each of the feature signatures
  return false;
}

bool unlockCar(void) {
  uint8_t eeprom_message[64];

  // Clear eeprom message
  ZERO(eeprom_message);

  // Initialize EEPROM
  if(EEPROMInit() != EEPROM_INIT_OK){
    return false;
  }
  // Load Unlock Success Message
  EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC, UNLOCK_EEPROM_SIZE);

  // Display Unlock Success Message
  uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

  // Clear eeprom message
  ZERO(eeprom_message);

  return true;
}

/**
 * @brief Function that handles starting of car - feature list
 */
void startCar(RESPONSE *response) {
  uint32_t i;
  uint8_t eeprom_message[64];

  // Print out feature messages for all active features
  for (i = 1; i <= NUM_FEATURES; i++) {
    package = (PACKAGE *packages)[i];
    if(memcmp(&package, NON_PACKAGE, sizeof(PACKAGE))) {
      // Initialize EEPROM
      if(EEPROMInit() != EEPROM_INIT_OK){
        return;
      }
      // Send feature message
      EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - i * FEATURE_SIZE, FEATURE_SIZE);
      uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
    }
  }
}

