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

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"

/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct {
  uint8_t car_id[8];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
} FEATURE_DATA;

typedef struct {//TODO
  uint8_t data[64];
} CHALLENGE;

typedef struct {//TODO
  uint8_t data[64];
} RESPONSE;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

/*** Function definitions ***/
// Core functions - tryUnlock and startCar
void tryUnlock(void);
void startCar(void);

// Declare password
const uint8_t pass[] = PASSWORD;
const uint8_t car_id[] = CAR_ID;

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

  // Zero out challenge and response
  memset(&challenge, 0, sizeof(challenge));
  memset(&response, 0, sizeof(response));

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

  // Zero out challenge and response
  memset(&challenge, 0, sizeof(challenge)) &&
  memset(&response, 0, sizeof(response)) &&
  
  // Unlock the car
  unlockCar() &&

  // Start the car
  startCar();
}

bool gen_challenge(CHALLENGE *challenge) {
  return false;
}

bool verify_response(CHALLENGE *challenge, RESPONSE *response) {
  //verify the challenge-response response
  //verify each of the feature signatures
  return false;
}

bool unlockCar() {
  uint8_t eeprom_message[64];

  // Zero out eeprom message
  memset(&eeprom_message, 0, sizeof(eeprom_message));

  // Load Unlock Success Message
  EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC, UNLOCK_EEPROM_SIZE);

  // Display Unlock Success Message
  uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

  // Zero out eeprom message
  memset(&eeprom_message, 0, sizeof(eeprom_message));

  return true;
}

/**
 * @brief Function that handles starting of car - feature list
 */
int startCar(void) {
  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;

  // Receive start message
  receive_board_message_by_type(&message, START_MAGIC);

  FEATURE_DATA *feature_info = (FEATURE_DATA *)buffer;

  // Verify correct car id
  if (strcmp((char *)car_id, (char *)feature_info->car_id)) {
    return;
  }

  // Print out features for all active features
  for (int i = 0; i < feature_info->num_active; i++) {
    uint8_t eeprom_message[64];

    uint32_t offset = feature_info->features[i] * FEATURE_SIZE;

    if (offset > FEATURE_END) {
        offset = FEATURE_END;
    }

    EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);

    uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
  }
}

