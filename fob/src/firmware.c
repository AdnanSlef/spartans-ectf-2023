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

/*** Globals to Handle Hardware Switch ***/
uint8_t previous_sw_state = GPIO_PIN_4;
uint8_t debounce_sw_state = GPIO_PIN_4;
uint8_t current_sw_state = GPIO_PIN_4;

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

  // This will run on first boot to initialize features
  if (fob_state_ram.feature_info.num_active == 0xFF)
  {
    fob_state_ram.feature_info.num_active = 0;
    saveFobState(&fob_state_ram);
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
        pPairFob(&fob_state_ram); //todo timeout
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

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void pPairFob(FLASH_DATA *fob_state_ram)
{

  if(!PFOB) {
    return;
  }

  // get pin from HOST_UART
  // if pin is invalid,
  //    sleep(5) and return
  // if pin is valid,
  //    send PIN to UFOB_UART
  //    send key to UFOB_UART

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

  if(!(UFOB && OG_UFOB)) {
    return;
  }

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
  if(!PFOB) {
    return;
  }

  // get package from Host UART
  // add it to our packages, implementation depending on functional requirements.
  // if we only need to support 1,2,3 then we don't even need dynamic-list-with-max-size, just a static array

  // reference design below
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    uint8_t uart_buffer[20];
    uart_readline(HOST_UART, uart_buffer);

    ENABLE_PACKET *enable_message = (ENABLE_PACKET *)uart_buffer;
    if (strcmp((char *)fob_state_ram->pair_info.car_id,
               (char *)enable_message->car_id))
    {
      return;
    }

    // Feature list full
    if (fob_state_ram->feature_info.num_active == NUM_FEATURES)
    {
      return;
    }

    // Search for feature in list
    for (int i = 0; i < fob_state_ram->feature_info.num_active; i++)
    {
      if (fob_state_ram->feature_info.features[i] == enable_message->feature)
      {
        return;
      }
    }

    fob_state_ram->feature_info
        .features[fob_state_ram->feature_info.num_active] =
        enable_message->feature;
    fob_state_ram->feature_info.num_active++;

    saveFobState(fob_state_ram);
    uart_write(HOST_UART, (uint8_t *)"Enabled", 7);
  }
}

/**
 * @brief Function that handles the fob unlocking a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void unlockCar(FLASH_DATA *fob_state_ram)
{
  if(!PFOB) {
    return;
  }

  // request unlock (send unlock magic byte to CAR_UART)
  // get challenge from CAR_UART
  // generate response
  // send response and features

  // reference design below
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    MESSAGE_PACKET message;
    message.message_len = 6;
    message.magic = UNLOCK_MAGIC;
    message.buffer = fob_state_ram->pair_info.password;
    send_board_message(&message);
  }
}

/**
 * @brief Function that handles the fob starting a car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void startCar(FLASH_DATA *fob_state_ram)
{
  if (fob_state_ram->paired == FLASH_PAIRED)
  {
    MESSAGE_PACKET message;
    message.magic = START_MAGIC;
    message.message_len = sizeof(FEATURE_DATA);
    message.buffer = (uint8_t *)&fob_state_ram->feature_info;
    send_board_message(&message);
  }
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