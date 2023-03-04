/**
 * @file firmware.h
 * @author Spartan State Security Team
 * @brief File that contains header information for the firmware of the key fob device
 * @date 2023
 */

#ifndef FOB_FIRMWARE_H
#define FOB_FIRMWARE_H

/*** Features Information ***/
#define NUM_FEATURES 3
#define FEATURE_END 0x7C0
#define FEATURE_SIZE 64

/*** Special Constants for Communication ***/
#define ENABLE_CMD 0x10
#define P_PAIR_CMD 0x20
#define U_PAIR_CMD 0x30
#define UNLOCK_REQ  0x56

/*** FLASH Storage Information ***/
#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF

/*** Structure definitions ***/
typedef sb_sw_signature_t PACKAGE;

typedef struct {
  uint8_t data[64];
} CHALLENGE;

typedef struct {
  sb_sw_signature_t unlock;
  PACKAGE feature1;
  PACKAGE feature2;
  PACKAGE feature3;
} RESPONSE;

// Defines a struct for the format of a pairing message
typedef struct
{
  sb_sw_private_t car_priv;
  uint32_t pin;
} PAIR_PACKET;

// Defines a struct for storing the state in flash
typedef struct
{
  uint32_t paired;
  uint32_t pin;
  sb_sw_private_t car_priv;
  PACKAGE feature1;
  PACKAGE feature2;
  PACKAGE feature3;
} FOB_DATA;

/*** Function definitions ***/
// Core functions
void unlockCar(FLASH_DATA *fob_state_ram);
void enableFeature(FLASH_DATA *fob_state_ram);
void pPairFob(FLASH_DATA *fob_state_ram);
void uPairFob(FLASH_DATA *fob_state_ram);
void startCar(FLASH_DATA *fob_state_ram);
void gen_response(CHALLENGE *challenge, RESPONSE *response);

// Helper functions
void tryHostCmd(void);
void tryButton(void);
void prep_drbg(void);
void saveFobState(FLASH_DATA *flash_data);
bool get_secret(sb_sw_private_t *priv, uint32_t *pin);
bool init_drbg(void);

#endif