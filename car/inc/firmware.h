/**
 * @file firmware.h
 * @author Spartan State Security Team
 * @brief File that contains header information for the firmware of the Secure Car device
 * @date 2023
 */

#ifndef CAR_FIRMWARE_H
#define CAR_FIRMWARE_H

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

// Features Information
#define NUM_FEATURES 3
#define FEATURE_END UNLOCK_EEPROM_LOC
#define FEATURE_SIZE 64

// Entropy
#define ENTROPY_FLASH 0x3FC00

// Endianness
#define ENDIAN 1

/*** Structure definitions ***/
typedef sb_sw_signature_t PACKAGE;

typedef struct {
  uint8_t data[64];
} CHALLENGE;

typedef struct {
  sb_sw_signature_t unlock;
  PACKAGE feature[3];
} RESPONSE;

typedef struct {
  sb_sw_public_t car_pubkey;
  sb_sw_public_t host_pubkey;
} CAR_DATA;

typedef struct {
  uint8_t data[0x400];
} ENTROPY;

/*** Function definitions ***/
// Core Functions
bool tryUnlock(void);
bool startCar(RESPONSE *response);
bool unlockCar(void);

// Security Functions
bool gen_challenge(CHALLENGE *challenge);
bool verify_response(CHALLENGE *challenge, RESPONSE *response);

// Helper Functions
void SLEEP(void);
bool init_drbg(void);

#endif