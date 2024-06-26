/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"
#include "../application_processor/inc/simple_crypto.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

#define KEYSIZE 128

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
    uint8_t key[32];
	uint8_t pubkey[KEYSIZE];
    bool ap_valid;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t validated;
int keysize = 1024; //change to size of the key in bits
uint8_t symkey[KEYSIZE];
uint8_t publicDERkey[KEYSIZE];
uint8_t privDERkey[KEYSIZE];
uint8_t privDERkey[KEYSIZE];
uint8_t apkey[KEYSIZE];
RNG * rng;
RsaKey * key;
/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
	uint8_t encryptedtext[len];
	uint8_t encryptedtext2[len];
	int error = encrypt_sym(buffer, len, symkey, encryptedtext); //-1 on bad length error, 0 if success
	//memcpy(buffer, encryptedtext, len);
	RsaKey * pkey;
    pkey = (RsaKey*)malloc(sizeof(RsaKey));
	wc_RsaPublicKeyDecode(apkey, apkey, pkey, keysize);
	int error2 = wc_RsaPublicencrypt(encryptedtext, len, encryptedtext2, len, pkey, rng);
    free(pkey);
    send_packet_and_ack(len, encryptedtext2); 
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
	int bytesreceived = wait_and_receive_packet(buffer);
	uint8_t ciphertext[bytesreceived];
	uint8_t ciphertext2[bytesreceived];
    RsaKey * pkey;
    pkey = (RsaKey*)malloc(sizeof(RsaKey));
    word32 idx = 0;
	wc_RsaPrivateKeyDecode(privDERkey, &idx, pkey, keysize);
	int error2 = wc_RsaPrivateDecryptInline(buffer, bytesreceived, &ciphertext2, pkey);
	memcpy(ciphertext, ciphertext2, bytesreceived); 
	decrypt_sym(ciphertext, bytesreceived, symkey, buffer);
    free(pkey);
    return bytesreceived;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
	LED_Off(LED3);
	MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;
    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:	
        uint8_t *check_ap;
        hash(AP_SECRET, 32, check_ap);
        if (memcmp(command->params, check_ap, 32) != 0) {
    	    validated = 0;
	    return;
        }
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate();
		memcpy(apkey, command->params, keysize);
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
	
	//basic validation check
	if(validated == 0) {
		return;
	}
	
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    secure_send(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    secure_send(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    memcpy(packet->key, COMP_SECRET);
    memcpy(packet->pubkey, publicDERkey);
	memcpy(transmit_buffer, packet, sizeof(validate_message));
    secure_send(sizeof(validate_message), transmit_buffer);
    int check = hash(COMP_SECRET, sizeof(COMP_SECRET),packet->key);    
	//assuming AP valid at this point
	if (check == 0) {
		validated = 1;
	}
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    secure_send(len, transmit_buffer);
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    validated = 0;
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

	// Set up RSA keys
    key = (RsaKey*)malloc(sizeof(RsaKey));
    rng = (RNG*)malloc(sizeof(RNG));
	long exponent = 42779; //pick any exponent

	wc_InitRng(rng);
	wc_Sha256Hash(AP_SECRET,keysize,symkey);
	
	if (wc_InitRsaKey(key, NULL)) {
		// Handle error
		printf("Failed to initialize RSA key");
	}

	if (wc_MakeRsaKey(key, keysize * 8, exponent, rng)) {
		// Handle error
		printf("Failed to make RSA key");
	}
	
	if (wc_RsaKeyToPublicDer(key, publicDERkey, sizeof(publicDERkey)) != 0) {
		// Handle Error
		printf("Failed to extract pubilc key from RSA key");
	}
	
	if (wc_RsaKeyToDer(key, privDERkey, sizeof(privDERkey)) != 0) {
		// Handle Error
		printf("Failed to extract private key from RSA key");
	}
	
    while (1) {
        secure_receive(receive_buffer);

        component_process_cmd();
    }
}
