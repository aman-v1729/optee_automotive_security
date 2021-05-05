#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include <authenticated_encryption_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

#define AES_TEST_BUFFER_SIZE 16
#define AES_TEST_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define DECODE 0
#define ENCODE 1

uint8_t public_exp[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";
uint8_t modulus[] = "\x80\x55\x45\x4b\x27\xd0\x55\x80\x7a\xc9\x12\x6b\x8e\x7b\xb2\x70\x01\x5f\x63\x0a\xb5\x5a\x74\xc9\x26\x88\x30\xbe\x10\x4d\xd6\x6c\x42\x5a\x9c\xe2\x94\x45\x52\xdb\xa0\x82\xe6\x2d\xbd\x7c\x84\x53\xd3\x32\x6e\xf2\x1e\xae\x1d\x5c\x10\x29\x45\xfa\xb8\x5f\xb3\x71\xe8\x76\x0d\x52\xc1\x2e\x68\xc7\x2a\x3a\x1d\xef\x7e\xe2\xd2\x87\xc2\xea\xb4\x91\xb4\xbe\x6e\xf1\x26\x68\xbd\x0a\x14\xb8\xdc\x5a\x60\xbd\x50\xbd\xa4\x87\x51\xaa\x99\x32\x2f\xe3\x1f\x76\x8e\x6f\xa1\x8f\xad\xf9\xf6\x98\xaa\x1a\xc6\x3b\x8f\x91\xc5\x89\xda\xfd";
uint8_t target_modulus[] = "\x91\xcc\x81\x63\x3d\xff\x41\x83\xc5\x7c\xf0\x65\x1b\x04\xa7\x57\x12\xba\xad\x7a\x76\x38\x2f\x84\x72\x1b\xd6\x44\x5c\x7b\x77\xbf\xb0\x07\x8d\x22\x50\xeb\xda\x40\x28\x3e\xf2\x0d\x69\x46\x34\x41\xa8\x36\x53\x32\x3d\x90\xb5\x5a\xf8\xd7\x1c\xcb\x6f\x25\x60\x7e\x5e\xaa\xac\x0a\xc7\x30\x80\x42\x32\xdc\x6e\x42\xce\xf7\x29\x26\xd2\xc6\x9e\x09\x54\x53\xca\x77\x55\xfd\x5e\x92\x69\x46\xde\x5c\x40\xfc\x84\x22\x32\x68\x8b\xc6\x90\x45\xee\xaf\xea\x7f\xcc\xc5\xa9\x48\xf9\x81\xf5\xf9\x65\x8d\x23\x3f\x3d\x02\x5f\x3e\x8c\x8f";
uint8_t target_public_exp[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";

struct ta_attrs
{
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_AUTHENTICATED_ENCRYPTION_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InitializeCOntext failed with code 0x%x\n", res);

	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
						   TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz)
{
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									  TEEC_MEMREF_TEMP_OUTPUT,
									  TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = (void *)in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = (void *)out;
	op->params[1].tmpref.size = out_sz;
}

// char hashed[64];

void send_to_tee(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz, uint32_t mode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	// printf("out : %s\n", out);

	prepare_op(&op, in, in_sz, out, out_sz);
	// printf("out2 : %s\n", out);

	res = TEEC_InvokeCommand(&ta->sess, mode, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nFAIL\n", res, origin);
	printf("Received from TEE: %s\n", (char *)op.params[1].tmpref.buffer);
	// char *ret;
	// ret = (char *)op.params[1].tmpref.buffer;
	// strcpy(hashed, ret);
}

void rsa_gen_keys(struct ta_attrs *ta, char *pub_key, size_t pub_key_sz, char *modulus, size_t modulus_sz, int priv)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = pub_key;
	op.params[0].tmpref.size = pub_key_sz;
	op.params[1].tmpref.buffer = modulus;
	op.params[1].tmpref.size = modulus_sz;
	char *gg = "g";
	op.params[2].tmpref.buffer = gg;
	op.params[2].tmpref.size = priv;
	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GENKEYS, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
	printf("\n=========== Keys set. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	printf("\n============ RSA ENCRYPT CA SIDE ============\n");
	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
			 res, origin);
	printf("\nThe text sent was encrypted: %s\n", out);
}

void rsa_decrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	printf("\n============ RSA DECRYPT CA SIDE ============\n");
	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_DECRYPT, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_DECRYPT) failed 0x%x origin 0x%x\n",
			 res, origin);
	printf("\nThe text sent was decrypted: %s\n", (char *)op.params[1].tmpref.buffer);
}

////////////////////////////////////////////////////////////////////////////

void prepare_aes(struct ta_attrs *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
									 TEEC_VALUE_INPUT,
									 TEEC_VALUE_INPUT,
									 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			 res, origin);
}

void set_key(struct ta_attrs *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			 res, origin);
}

void set_iv(struct ta_attrs *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			 res, origin);
}

void cipher_buffer(struct ta_attrs *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_OUTPUT,
									 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			 res, origin);
}
////////////////////////////////////////////////////////////////////////////////

TEEC_Result read_secure_object(struct ta_attrs *ctx, char *id,
							   char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_OUTPUT,
									 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
							 TA_SECURE_STORAGE_CMD_READ_RAW,
							 &op, &origin);
	switch (res)
	{
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result write_secure_object(struct ta_attrs *ctx, char *id,
								char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_INPUT,
									 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;

	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
							 TA_SECURE_STORAGE_CMD_WRITE_RAW,
							 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res)
	{
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

int main(int argc, char *argv[])
{
	struct ta_attrs ta;
	prepare_ta_session(&ta);

	int bufferLength = 128;
	char msg[bufferLength];

	// FILE *infile;
	// char *buffer;
	// long numbytes;
	// infile = fopen("message.txt", "r");

	// if (infile == NULL)
	// 	return 1;

	// fseek(infile, 0L, SEEK_END);
	// numbytes = ftell(infile);

	// fseek(infile, 0L, SEEK_SET);

	// buffer = (char *)calloc(numbytes, sizeof(char));

	// if (buffer == NULL)
	// 	return 1;

	// fread(buffer, sizeof(char), numbytes, infile);
	// fclose(infile);

	// strcpy(msg, buffer);
	// free(buffer);

	// send_to_tee(&ta, msg, bufferLength, out, bufferLength, TA_PLAIN_TEXT);

	// char key[AES_TEST_KEY_SIZE];
	// char iv[AES_BLOCK_SIZE];
	// char clear[AES_TEST_BUFFER_SIZE];
	// char ciph[AES_TEST_BUFFER_SIZE];
	// char temp[AES_TEST_BUFFER_SIZE];

	// char key_id[] = "aeskey";
	// char read_data[AES_TEST_BUFFER_SIZE];
	// TEEC_Result res;

	// strcpy(key, "some Random key1");

	// printf("- Create and load object in the TA secure storage\n");
	// res = write_secure_object(&ta, key_id,
	// 						  key, sizeof(key));
	// if (res != TEEC_SUCCESS)
	// 	errx(1, "Failed to create an object in the secure storage");

	// // printf("- Read back: \n");
	// // res = read_secure_object(&ta, key_id,
	// // 						 read_data, sizeof(read_data));
	// // if (res != TEEC_SUCCESS)
	// // 	errx(1, "Failed to read an object from the secure storage");

	// // printf("%s\n", read_data);

	// printf("Prepare encode operation\n");
	// prepare_aes(&ta, ENCODE);

	// printf("Load key in TA\n");
	// // memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	// strcpy(key, "unused value - filler");
	// set_key(&ta, key, AES_TEST_KEY_SIZE);

	// printf("Reset ciphering operation in TA (provides the initial vector)\n");
	// // memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	// strcpy(iv, "Some Random IV12");
	// set_iv(&ta, iv, AES_BLOCK_SIZE);

	// printf("Encode buffer from TA\n");
	// // memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
	// strcpy(clear, msg);
	// printf("%s\n\n\n\n", clear);
	// fflush(stdout);
	// cipher_buffer(&ta, clear, ciph, AES_TEST_BUFFER_SIZE);
	// printf("%s\n\n\n\n", clear);
	// fflush(stdout);
	// printf("%s\n\n\n\n", ciph);
	// fflush(stdout);

	// printf("Prepare decode operation\n");
	// prepare_aes(&ta, DECODE);

	// printf("Load key in TA\n");
	// // memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	// strcpy(key, "unused value - filler");
	// set_key(&ta, key, AES_TEST_KEY_SIZE);

	// printf("Reset ciphering operation in TA (provides the initial vector)\n");
	// // memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	// strcpy(iv, "Some Random IV12");
	// set_iv(&ta, iv, AES_BLOCK_SIZE);

	// printf("Decode buffer from TA\n");
	// cipher_buffer(&ta, ciph, temp, AES_TEST_BUFFER_SIZE);

	// printf("%s\n\n\n\n", clear);
	// fflush(stdout);
	// printf("%s\n\n\n\n", ciph);
	// fflush(stdout);
	// printf("%s\n\n\n\n", temp);
	// fflush(stdout);

	// /* Check decoded is the clear content */
	// if (memcmp(msg, temp, AES_TEST_BUFFER_SIZE))
	// 	printf("Clear text and decoded text differ => ERROR\n");
	// else
	// 	printf("Clear text and decoded text match\n");

	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	char sign[RSA_MAX_PLAIN_LEN_1024];
	char sign_verif[RSA_CIPHER_LEN_1024];
	char decrypted[RSA_MAX_PLAIN_LEN_1024];
	char store_id[] = "ctext";
	char hashed[bufferLength];

	// send_to_tee(&ta, ciph, RSA_CIPHER_LEN_1024, hashed, 64, TA_SHA256);
	// if (argc > 1 && strcmp(argv[1], "enc") == 0)
	// {
	rsa_gen_keys(&ta, target_public_exp, 128, target_modulus, 128, 3);
	printf("\nType something to be encrypted and decrypted in the TA:\n");
	fflush(stdin); //setbuf(stdin, NULL);
	fgets(clear, sizeof(clear), stdin);
	// // printf("%d", strlen(clear));
	rsa_encrypt(&ta, clear, strlen(clear) + 1, ciph, RSA_CIPHER_LEN_1024);
	// // printf("%d", strlen(ciph));
	fflush(stdout);
	rsa_gen_keys(&ta, public_exp, 128, modulus, 128, 4);
	send_to_tee(&ta, ciph, bufferLength, hashed, bufferLength, TA_PLAIN_TEXT);
	send_to_tee(&ta, ciph, bufferLength, hashed, bufferLength, TA_SHA256);
	char *hash;
	hash = hashed;
	rsa_encrypt(&ta, hash, 32, sign, RSA_CIPHER_LEN_1024);

	// TEEC_Result res = write_secure_object(&ta, store_id, ciph, sizeof(ciph));
	// if (res != TEEC_SUCCESS)
	// 	errx(1, "Failed to create an object in the secure storage");
	// }
	// if (argc == 3)
	// {

	fflush(stdout);
	// rsa_gen_keys(&ta, public_exp, 128, modulus, 128, 4);
	send_to_tee(&ta, ciph, bufferLength, hashed, bufferLength, TA_PLAIN_TEXT);
	send_to_tee(&ta, ciph, RSA_CIPHER_LEN_1024, hashed, 64, TA_SHA256);
	rsa_decrypt(&ta, sign, RSA_CIPHER_LEN_1024, sign_verif, RSA_MAX_PLAIN_LEN_1024);
	fflush(stdout);
	rsa_gen_keys(&ta, target_public_exp, 128, target_modulus, 128, 3);
	printf("\n\n\nenc:%s\n\n\n", ciph);
	rsa_decrypt(&ta, ciph, RSA_CIPHER_LEN_1024, decrypted, RSA_MAX_PLAIN_LEN_1024);
	// // printf("%d", strlen(decrypted));
	// }
	fflush(stdout);
	terminate_tee_session(&ta);
	return 0;
}
