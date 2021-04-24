#ifndef TA_TEST_H
#define TA_TEST_H

#define TA_TEST_UUID \
    { 0x3176d7b6, 0x78ee, 0x4ad7, \
        { 0x8d, 0x65, 0xbc, 0xbd, 0xc9, 0x49, 0x97, 0x09 } }

// #define TA_PRIVATE_KEY 
// #define TA_PUBLIC_KEY
// #define  

// The function IDs implemented in this TA 
#define TA_SHA256		    0
#define TA_PLAIN_TEXT		1

/*
 * TA_SECURE_STORAGE_CMD_READ_RAW - Create and fill a secure storage file
 * param[0] (memref) ID used the identify the persistent object
 * param[1] (memref) Raw data dumped from the persistent object
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_CMD_READ_RAW		3

/*
 * TA_SECURE_STORAGE_CMD_WRITE_RAW - Create and fill a secure storage file
 * param[0] (memref) ID used the identify the persistent object
 * param[1] (memref) Raw data to be writen in the persistent object
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_CMD_WRITE_RAW		4

/*
 * TA_SECURE_STORAGE_CMD_DELETE - Delete a persistent object
 * param[0] (memref) ID used the identify the persistent object
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_CMD_DELETE		5




#endif