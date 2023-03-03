/**
 * @file firmware.h
 * @author Spartan State Security Team
 * @brief File that contains header information for the firmware of the car device
 * @date 2023
 */

#ifndef CAR_FIRMWARE_H
#define CAR_FIRMWARE_H

/*** Features Information ***/
#define NUM_FEATURES 3
#define FEATURE_END 0x7C0
#define FEATURE_SIZE 64

/*** Structure definitions ***/
typedef sb_sw_signature_t PACKAGE;

typedef struct {//TODO
  uint8_t data[64];
} CHALLENGE;

typedef struct {
  sb_sw_signature_t unlock;
  sb_sw_signature_t feature1;
  sb_sw_signature_t feature2;
  sb_sw_signature_t feature3;
} RESPONSE;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

/*** Function definitions ***/
// Core functions
void tryUnlock(void);
bool startCar(void);
bool unlockCar(void);

// Security Functions
bool gen_challenge(CHALLENGE *challenge);
bool verify_response(CHALLENGE *challenge, RESPONSE *response);

#endif