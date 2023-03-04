/**
 * @file firmware.c
 * @author Spartan State Security Team
 * @brief Secure Key Fob Implementation
 * @date 2023
 *
 * This source file is part of our designed system
 * for MITRE's 2023 Embedded System CTF (eCTF).
 * It implements the primary functionality of the keyfob device.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

// #include "sb_all.h"

#include "secrets.h"

#include "board_link.h"
#include "uart.h"
#include "firmware.h"

/*** Macros ***/
#define ZERO(M) memset(&M, 0, sizeof(M))

/*** Globals ***/
// Handle Hardware Switch
uint8_t previous_sw_state = GPIO_PIN_4;
uint8_t debounce_sw_state = GPIO_PIN_4;
uint8_t current_sw_state = GPIO_PIN_4;
// CSPRNG State
sb_hmac_drbg_state_t drbg;


/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void)
{
  FLASH_DATA fob_state_ram;
  FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;

// If paired fob, initialize the system information
#if PAIRED == 1
  if (fob_state_flash->paired == FLASH_UNPAIRED)
  {
    strcpy((char *)(fob_state_ram.pair_info.password), PASSWORD);
    strcpy((char *)(fob_state_ram.pair_info.pin), PAIR_PIN);
    strcpy((char *)(fob_state_ram.pair_info.car_id), CAR_ID);
    strcpy((char *)(fob_state_ram.feature_info.car_id), CAR_ID);
    fob_state_ram.paired = FLASH_PAIRED;

    saveFobState(&fob_state_ram);
  }
#else
  fob_state_ram.paired = FLASH_UNPAIRED;
#endif

  if (fob_state_flash->paired == FLASH_PAIRED)
  {
    memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
  }

  // This will run on first boot to initialize features, TODO remove except on first boot need to pull eeprom to flash
  if (fob_state_ram.feature_info.num_active == 0xFF)
  {
    fob_state_ram.feature_info.num_active = 0;
    saveFobState(&fob_state_ram);
  }

  // Initialize DRBG
  if (!init_drbg()) {
    return -1;
  }

  // Initialize HOST UART
  uart_init();

  // Initialize board link UART
  setup_board_link();

  // Setup SW1
  GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
  GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                   GPIO_PIN_TYPE_STD_WPU);

  // Infinite loop to register and handle commands
  while (true)
  {

    // Check for command from HOST
    tryHostCmd();

    // Check for button press
    tryButton();

  }
}

void tryHostCmd(void) {
  // Non blocking UART polling
  if (uart_avail(HOST_UART))
  {
    uint8_t cmd = (uint8_t)uart_readb(HOST_UART);

    if(cmd == ENABLE_CMD) {
      // if fob is paired, enable feature
      if(PFOB) {
        enableFeature(&fob_state_ram);
      }
    }
    if(cmd == P_PAIR_CMD) {
      // if fob is paired, pair another fob
      if(PFOB) {
        pPairFob(&fob_state_ram);
      }
    }
    if(cmd == U_PAIR_CMD) {
      // if fob is unpaired, pair fob
      if(UFOB && OG_UFOB) {
        uPairFob(&fob_state_ram);
      }
    }

  }
}

void tryButton(void) {

  current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);

  if ((current_sw_state != previous_sw_state) && (current_sw_state == 0)) {
    // Debounce switch
    SysCtlDelay(20000);
    debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);

    if (debounce_sw_state == current_sw_state) {
      // switch pressed, unlock car if paired
      if(PFOB) {
        unlockCar(&fob_state_ram);
      }
    }

  }
  previous_sw_state = current_sw_state;
}


bool init_drbg(void)
{
  ENTROPY temp_entropy;
  sb_sw_private_t car_privkey;

  // Check for Entropy Error
  ((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[1] &&
  ((uint32_t*)ENTROPY_FLASH)[2] == ((uint32_t*)ENTROPY_FLASH)[3] &&
  ((uint32_t*)ENTROPY_FLASH)[0] == ((uint32_t*)ENTROPY_FLASH)[4] &&
  return false;

  // Initialize DRBG
  get_secret(&car_privkey, NULL) &&
  sb_hmac_drbg_init(&drbg, ENTROPY_FLASH, sizeof(ENTROPY), car_privkey, sizeof(sb_sw_private_t), "Spartans", 8) == SB_SUCCESS
  || return false;

  // Clear private key
  ZERO(car_privkey);

  //Checkout Entropy
  memcpy(&temp_entropy, ENTROPY_FLASH, sizeof(ENTROPY));

  // Update Entropy
  sb_hmac_drbg_generate(&drbg, temp_entropy, sizeof(temp_entropy)) == SB_SUCCESS
  || return false;

  //Commit Entropy
  !FlashErase(ENTROPY_FLASH) &&
  !FlashProgram(&temp_entropy, ENTROPY_FLASH, sizeof(ENTROPY)) &&
  return true;
}

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void pPairFob(FLASH_DATA *fob_state_ram)
{
  // Paired fob only
  PFOB || return;

  // get pin from HOST_UART
  // if pin is invalid,
  //    sleep(5) and return
  // if pin is valid,
  //    send PIN to UFOB_UART
  //    send key to UFOB_UART

  // reference design below
  MESSAGE_PACKET message;
  // Start pairing transaction - fob is already paired
  int16_t bytes_read;
  uint8_t uart_buffer[8];
  uart_write(HOST_UART, (uint8_t *)"P", 1);
  bytes_read = uart_readline(HOST_UART, uart_buffer);

  if (bytes_read == 6)
  {
    // If the pin is correct
    if (!(strcmp((char *)uart_buffer,
                  (char *)fob_state_ram->pair_info.pin)))
    {
      // Pair the new key by sending a PAIR_PACKET structure
      // with required information to unlock door
      message.message_len = sizeof(PAIR_PACKET);
      message.magic = PAIR_MAGIC;
      message.buffer = (uint8_t *)&fob_state_ram->pair_info;
      send_board_message(&message);
    }
  }
}

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void uPairFob(FLASH_DATA *fob_state_ram)
{
  uint32_t PIN;
  TODO_KEYTYPE key;

  // original unpaired fob only
  if(!(UFOB && OG_UFOB)) {
    return;
  }

  FOB_DATA data;
  // get_PIN(&PIN, PFOB_UART)
  // get_key(&key, PFOB_UART)
  // set_PIN(PIN)
  // set_key(key)
  // PFOB true, UFOB false


  // reference design below
  MESSAGE_PACKET message;
  // Start pairing transaction - fob is not paired
  message.buffer = (uint8_t *)&fob_state_ram->pair_info;
  receive_board_message_by_type(&message, PAIR_MAGIC);
  fob_state_ram->paired = FLASH_PAIRED;
  strcpy((char *)fob_state_ram->feature_info.car_id,
          (char *)fob_state_ram->pair_info.car_id);

  uart_write(HOST_UART, (uint8_t *)"Paired", 6);

  saveFobState(fob_state_ram);
}

/**
 * @brief Function that handles enabling a new feature on the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void enableFeature(FLASH_DATA *fob_state_ram)
{
  PACKAGE package;
  
  // Paired fob only
  PFOB || return;

  // Get the feature number from the host
  uint8_t feature_num = (uint8_t)uart_readb(HOST_UART) - 1;

  // Get the package for the feature from the host
  uart_read(CAR_UART, &package, sizeof(PACKAGE));

  // Store the feature package
  if(feature_num < NUM_FEATURES) {
    // TODO checkout flash data
    memcpy(temp_flash.packages[feature_num], package, sizeof(PACKAGE));
    // TODO commit flash data, based on saveFobState
  }
}

bool get_secret(sb_sw_private_t *priv, uint32_t *pin) {
  #if OG_PFOB == 1
    if(EEPROMInit() != EEPROM_INIT_OK){
      return false;
    }
    if(priv) {
      EEPROMRead(priv, offsetof(FOB_DATA, car_privkey), sizeof(sb_sw_private_t));
    }
    if(pin) {
      EEPROMRead(pin, offsetof(FOB_DATA, pin), sizeof(uint32_t));
    }
    return true;
  #endif
  #if OG_UFOB == 1
    if(priv) {
      memcpy(priv, FLASH_DATA.car_privkey, sizeof(sb_sw_private_t));
    }
    if(pin) {
      *pin = FOB_DATA_FLASH.pin;
    }
    return true;
  #endif
}

/**
 * @brief Function that handles the fob unlocking a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void unlockCar(FLASH_DATA *fob_state_ram)
{
  CHALLENGE challenge;
  RESPONSE response;

  // Paired fob only
  PFOB || return;

  // Request the Car to Unlock
  request_unlock();

  // Receive Unlock Challenge from Car
  get_challenge(&challenge);
  
  // Generate Response
  gen_response(&challenge, &response);
  
  // Prepare Feature Requests
  memcpy(&response.feature1, self_flash.packages, sizeof(response.feature1)*3);

  // Send Response with Features
  finalize_unlock(&response);
}


void gen_response(CHALLENGE *challenge, RESPONSE *response)
{
  sb_sw_context_t sb_ctx;
  sb_sw_message_digest_t _hash;
  sb_sw_private_t priv;

  // Only paired fobs respond to challenges
  PFOB || return;

  // Clear empy data
  ZERO(sb_ctx);

  // Prepare DRBG
  prep_drbg();

  // Get signing key
  get_secret(priv, NULL) || return;
  
  // Generate response
  sb_sw_sign_message_sha256(&ctx, &_hash, &response->unlock, &priv, &challenge->data, sizeof(challenge->data), &drbg, SB_SW_CURVE_P256, ENDIAN);

  // Clear key
  ZERO(priv);
}

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data)
{
  FlashErase(FOB_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
}