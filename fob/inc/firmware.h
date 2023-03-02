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
// Defines a struct for the format of an enable message
typedef struct
{
  uint8_t car_id[8];
  uint8_t feature;
} ENABLE_PACKET;

// Defines a struct for the format of a pairing message
typedef struct
{
  uint8_t car_id[8];
  uint8_t password[8];
  uint8_t pin[8];
} PAIR_PACKET;

// Defines a struct for the format of start message
typedef struct
{
  uint8_t car_id[8];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
} FEATURE_DATA;

// Defines a struct for storing the state in flash
typedef struct
{
  uint8_t paired;
  PAIR_PACKET pair_info;
  FEATURE_DATA feature_info;
} FLASH_DATA;

/*** Function definitions ***/
// Core functions
void unlockCar(FLASH_DATA *fob_state_ram);
void enableFeature(FLASH_DATA *fob_state_ram);
void startCar(FLASH_DATA *fob_state_ram);

// Helper functions
void tryHostCmd(void);
void tryButton(void) 
void saveFobState(FLASH_DATA *flash_data);
void pairFob(FLASH_DATA *fob_state_ram);

#endif