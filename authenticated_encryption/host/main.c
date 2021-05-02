#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include <authenticated_encryption_ta.h>

#define AES_TEST_BUFFER_SIZE 16
#define AES_TEST_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define DECODE 0
#define ENCODE 1

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

void send_to_tee(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz, uint mode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, mode, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nFAIL\n", res, origin);
	printf("Received from TEE: %s\n", (char *)op.params[1].tmpref.buffer);
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

	int bufferLength = 1024;
	char msg[bufferLength];
	char out[bufferLength];

	FILE *infile;
	char *buffer;
	long numbytes;
	infile = fopen("message.txt", "r");

	if (infile == NULL)
		return 1;

	fseek(infile, 0L, SEEK_END);
	numbytes = ftell(infile);

	fseek(infile, 0L, SEEK_SET);

	buffer = (char *)calloc(numbytes, sizeof(char));

	if (buffer == NULL)
		return 1;

	fread(buffer, sizeof(char), numbytes, infile);
	fclose(infile);

	strcpy(msg, buffer);
	free(buffer);

	send_to_tee(&ta, msg, bufferLength, out, bufferLength, TA_PLAIN_TEXT);

	char key[AES_TEST_KEY_SIZE];
	char iv[AES_BLOCK_SIZE];
	char clear[AES_TEST_BUFFER_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	char temp[AES_TEST_BUFFER_SIZE];

	char key_id[] = "aeskey";
	char read_data[AES_TEST_BUFFER_SIZE];
	TEEC_Result res;

	strcpy(key, "some Random key1");

	printf("- Create and load object in the TA secure storage\n");
	res = write_secure_object(&ta, key_id,
							  key, sizeof(key));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to create an object in the secure storage");

	// printf("- Read back: \n");
	// res = read_secure_object(&ta, key_id,
	// 						 read_data, sizeof(read_data));
	// if (res != TEEC_SUCCESS)
	// 	errx(1, "Failed to read an object from the secure storage");

	// printf("%s\n", read_data);

	printf("Prepare encode operation\n");
	prepare_aes(&ta, ENCODE);

	printf("Load key in TA\n");
	// memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	strcpy(key, "unused value - filler");
	set_key(&ta, key, AES_TEST_KEY_SIZE);

	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	// memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	strcpy(iv, "Some Random IV12");
	set_iv(&ta, iv, AES_BLOCK_SIZE);

	printf("Encode buffer from TA\n");
	// memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
	strcpy(clear, msg);
	printf("%s\n\n\n\n", clear);
	fflush(stdout);
	cipher_buffer(&ta, clear, ciph, AES_TEST_BUFFER_SIZE);
	printf("%s\n\n\n\n", clear);
	fflush(stdout);
	printf("%s\n\n\n\n", ciph);
	fflush(stdout);

	printf("Prepare decode operation\n");
	prepare_aes(&ta, DECODE);

	printf("Load key in TA\n");
	// memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	strcpy(key, "unused value - filler");
	set_key(&ta, key, AES_TEST_KEY_SIZE);

	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	// memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	strcpy(iv, "Some Random IV12");
	set_iv(&ta, iv, AES_BLOCK_SIZE);

	printf("Decode buffer from TA\n");
	cipher_buffer(&ta, ciph, temp, AES_TEST_BUFFER_SIZE);

	printf("%s\n\n\n\n", clear);
	fflush(stdout);
	printf("%s\n\n\n\n", ciph);
	fflush(stdout);
	printf("%s\n\n\n\n", temp);
	fflush(stdout);

	/* Check decoded is the clear content */
	if (memcmp(msg, temp, AES_TEST_BUFFER_SIZE))
		printf("Clear text and decoded text differ => ERROR\n");
	else
		printf("Clear text and decoded text match\n");

	terminate_tee_session(&ta);
	return 0;
}
