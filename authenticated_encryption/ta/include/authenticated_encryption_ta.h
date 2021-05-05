
#ifndef TA_AUTHENTICATED_ENCRYPTION_H
#define TA_AUTHENTICATED_ENCRYPTION_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_AUTHENTICATED_ENCRYPTION_UUID                   \
	{                                                      \
		0x9878a26c, 0x51d2, 0x4028,                        \
		{                                                  \
			0x94, 0x6e, 0xc4, 0x0f, 0xa8, 0xf5, 0x15, 0x25 \
		}                                                  \
	}

#define TA_AES_ALGO_ECB 0
#define TA_AES_ALGO_CBC 1
#define TA_AES_ALGO_CTR 2

#define TA_AES_SIZE_128BIT (128 / 8)
#define TA_AES_SIZE_256BIT (256 / 8)

#define TA_AES_MODE_ENCODE 1
#define TA_AES_MODE_DECODE 0

/* The function IDs implemented in this TA */
#define TA_PLAIN_TEXT 0
#define TA_AES_CMD_PREPARE 1
#define TA_AES_CMD_SET_KEY 2

/*
 * TA_AES_CMD_SET_IV - reset IV
 * param[0] (memref) initial vector, size shall equal block length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_SET_IV 3

/*
 * TA_AES_CMD_CIPHER - Cipher input buffer into output buffer
 * param[0] (memref) input buffer
 * param[1] (memref) output buffer (shall be bigger than input buffer)
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_CIPHER 4
#define TA_SECURE_STORAGE_CMD_WRITE_RAW 5
#define TA_SECURE_STORAGE_CMD_READ_RAW 6

#define TA_RSA_CMD_GENKEYS 7
#define TA_RSA_CMD_ENCRYPT 8
#define TA_RSA_CMD_DECRYPT 9

#define TA_SHA256 10

#endif /*TA_AUTHENTICATED_ENCRYPTION_H*/
