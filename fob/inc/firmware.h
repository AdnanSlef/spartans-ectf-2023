/**
 * @file firmware.h
 * @author Spartan State Security Team
 * @brief File that contains header information for the firmware of the key fob device
 * @date 2023
 */

#ifndef FOB_FIRMWARE_H
#define FOB_FIRMWARE_H

#include "sb_all.h"

/*** Macro Definitions ***/
// Features Information
#define NUM_FEATURES 3
#define FEATURE_END 0x7C0
#define FEATURE_SIZE 64

// Paired or Unpaired
#define PFOB pfob()
#define UFOB !pfob()

// Endianness
#define ENDIAN 1

// Entropy
#define ENTROPY_FLASH 0x3F800

/*** Special Constants for Communication ***/
#define ENABLE_CMD 0x10
#define P_PAIR_CMD 0x20
#define U_PAIR_CMD 0x30
#define UNLOCK_REQ 0x56
#define NO_UPAIRED 0xFFFFFFFF
#define YES_PAIRED 0x20202020

/*** FLASH Storage Information ***/
#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF
#define FOB_FLASH ((FOB_DATA *)FOB_STATE_PTR)

/*** Structure definitions ***/
typedef sb_sw_signature_t PACKAGE;

typedef struct {
  uint8_t data[64];
} CHALLENGE;

// Defines a struct of the response for the challenge-response mechanism
typedef struct {
  sb_sw_signature_t unlock;
  PACKAGE feature1;
  PACKAGE feature2;
  PACKAGE feature3;
} RESPONSE;

// Defines a struct for the format of a pairing message
typedef struct
{
  sb_sw_private_t car_privkey;
  uint32_t pin;
} PAIR_PACKET;

// Defines a struct for storing the fob data
typedef struct
{
  uint32_t paired;
  uint32_t pin;
  sb_sw_private_t car_privkey;
  PACKAGE feature[3];
} FOB_DATA;

// Defines a struct for storing entropy in flash
typedef struct {
  uint8_t data[0x400];
} ENTROPY;

/*** Function definitions ***/
// Core functions
void pPairFob(void);
void uPairFob(void);
void enableFeature(void);
void unlockCar(void);
void gen_response(CHALLENGE *challenge, RESPONSE *response);

// Helper functions
void tryHostCmd(void);
void tryButton(void);
bool init_drbg(void);
void SLEEP(void);
bool pfob(void);
bool get_secret(sb_sw_private_t *priv, uint32_t *pin);
void loadFobState(FOB_DATA *fob_data);
bool saveFobState(FOB_DATA *fob_data);

#endif