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

#include "driverlib/flash.h"
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

/*** Globals ***/
// CSPRNG State
sb_hmac_drbg_state_t drbg;

const uint8_t NON_PACKAGE[sizeof(PACKAGE)] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};

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

  // Establish Entropy if Needed
  if(((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[1] &&
     ((uint32_t*)ENTROPY_FLASH)[2] == ((uint32_t*)ENTROPY_FLASH)[3] &&
     ((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[4]) {

    if( FlashErase(ENTROPY_FLASH)
     || FlashProgram((uint32_t *)&S_ENTROPY, ENTROPY_FLASH, sizeof(ENTROPY))
    ) return -1;
    
  }

  // Initialize DRBG
  if (!init_drbg()) {
    return -1;
  }

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  while (true) {

    tryUnlock();
  }
}

/**
 * @brief Sleeps for 5 seconds
 *
 */
void SLEEP(void) {
  // (16000000/3)*5
  SysCtlDelay(26666665);
}

/**
 * @brief Function that handles unlocking of car
 */
bool tryUnlock(void) {
  CHALLENGE challenge;
  RESPONSE response;

  // Clear response
  ZERO(response);

  return // Ensure the below code isn't optimized out

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
  startCar(&response);
}

bool init_drbg(void)
{
  ENTROPY temp_entropy;
  sb_sw_public_t car_pubkey;

  // Check for Entropy Error; TODO get the entropy into flash to begin with
  if(((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[1] &&
     ((uint32_t*)ENTROPY_FLASH)[2] == ((uint32_t*)ENTROPY_FLASH)[3] &&
     ((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[4])
     return false;

  // Get Car Public Key from EEPROM
  if(EEPROMInit() != EEPROM_INIT_OK) return false;
  EEPROMRead((uint32_t *)&car_pubkey, offsetof(CAR_DATA, car_pubkey), sizeof(car_pubkey));

  // Check for EEPROM Error
  if(((uint32_t*)&car_pubkey)[0] == ((uint32_t*)&car_pubkey)[1] &&
     ((uint32_t*)&car_pubkey)[2] == ((uint32_t*)&car_pubkey)[3])
     return false;

  // Initialize DRBG
  if(sb_hmac_drbg_init(&drbg, (void *)ENTROPY_FLASH, sizeof(ENTROPY),
                       (sb_byte_t *)&car_pubkey, sizeof(sb_sw_public_t), (sb_byte_t *)"Spartans", 8)
     != SB_SUCCESS)
     return false;

  // Checkout Entropy
  memcpy(&temp_entropy, (void *)ENTROPY_FLASH, sizeof(ENTROPY));

  // Update Entropy
  if(sb_hmac_drbg_generate(&drbg, (sb_byte_t *)&temp_entropy, sizeof(temp_entropy)) != SB_SUCCESS) return false;

  // Commit Entropy
  if(FlashErase(ENTROPY_FLASH) || FlashProgram((uint32_t *)&temp_entropy, ENTROPY_FLASH, sizeof(ENTROPY))) return false;
  
  // Success
  return true;
}

bool gen_challenge(CHALLENGE *challenge) {
  return sb_hmac_drbg_generate(&drbg, (sb_byte_t *)challenge, sizeof(CHALLENGE)) == SB_SUCCESS;
}

bool verify_response(CHALLENGE *challenge, RESPONSE *response) {
  sb_sw_context_t sb_ctx;
  sb_sha256_state_t sha;
  sb_sw_message_digest_t hash;
  sb_sw_public_t host_pubkey;
  sb_sw_public_t car_pubkey;
  PACKAGE package;
  uint8_t i;

  // Get Public Keys from EEPROM
  if(EEPROMInit() != EEPROM_INIT_OK) return false;
  EEPROMRead((uint32_t *)&car_pubkey, offsetof(CAR_DATA, car_pubkey), sizeof(car_pubkey));
  EEPROMRead((uint32_t *)&host_pubkey, offsetof(CAR_DATA, host_pubkey), sizeof(host_pubkey));

  // Verify the challenge-response response
  if(sb_sw_verify_signature_sha256(&sb_ctx, &hash, &response->unlock, &car_pubkey,
                                   (sb_byte_t *)challenge, sizeof(CHALLENGE), &drbg, SB_SW_CURVE_P256, ENDIAN)
     != SB_SUCCESS)
     return false;
  ZERO(sb_ctx);
  ZERO(hash);

  // Verify each of the feature signatures
  for(i=0; i<NUM_FEATURES; i++) {
    package = response->feature[i];
    if(memcmp(&package, &NON_PACKAGE, sizeof(PACKAGE))) {
      sb_sha256_init(&sha);
      sb_sha256_update(&sha, (sb_byte_t *)&car_pubkey, sizeof(car_pubkey));
      sb_sha256_update(&sha, &i, sizeof(i));
      sb_sha256_finish(&sha, (sb_byte_t *)&hash);
      if(sb_sw_verify_signature(&sb_ctx, &package, &host_pubkey, &hash, &drbg, SB_SW_CURVE_P256, ENDIAN) != SB_SUCCESS) {
        return false;
      }
    }
  }
  return true;
}

bool unlockCar(void) {
  uint8_t eeprom_message[UNLOCK_EEPROM_SIZE];

  // Clear eeprom message
  ZERO(eeprom_message);

  // Initialize EEPROM
  if(EEPROMInit() != EEPROM_INIT_OK){
    return false;
  }
  // Load Unlock Success Message
  EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC, sizeof(eeprom_message));

  // Display Unlock Success Message
  uart_write(HOST_UART, eeprom_message, sizeof(eeprom_message));

  // Clear eeprom message
  ZERO(eeprom_message);

  return true;
}

/**
 * @brief Function that handles starting of car - feature list
 */
bool startCar(RESPONSE *response) {
  uint32_t i;
  uint8_t eeprom_message[FEATURE_SIZE];
  PACKAGE package;

  // Print out feature messages for all active features
  for (i = 0; i < NUM_FEATURES; i++) {
    package = response->feature[i];
    if(memcmp(&package, &NON_PACKAGE, sizeof(PACKAGE))) {
      // Initialize EEPROM
      if(EEPROMInit() != EEPROM_INIT_OK){
        return false;
      }
      // Send feature message
      EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - (i+1) * FEATURE_SIZE, sizeof(eeprom_message));
      uart_write(HOST_UART, eeprom_message, sizeof(eeprom_message));
    }
  }
  return true;
}

