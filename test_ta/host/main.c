#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <test_ta.h>


struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
    TEEC_UUID uuid = TA_TEST_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ta -> ctx);
    if(res != TEEC_SUCCESS) errx(1, "\nTEEC_InitializeCOntext failed with code 0x%x\n", res);
    
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


void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = (void *) in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = (void *) out;
	op->params[1].tmpref.size = out_sz;
}


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
	switch (res) {
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

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(struct ta_attrs *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}



	return res;
}






char *ret;
char hashed[32];

void send_to_tee(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz, uint32_t mode)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    // printf("out : %s\n", out);

    prepare_op(&op, in, in_sz, out, out_sz);
    // printf("out2 : %s\n", out);

    res = TEEC_InvokeCommand(&ta->sess, mode, &op, &origin);
    // if(res != TEEC_SUCCESS)
        // errx(1, "\nFAIL\n", res, origin);
    printf("Received from TEE: %s\n", (char *) op.params[1].tmpref.buffer);
    ret = (char *)op.params[1].tmpref.buffer;
	strcpy(hashed,ret);
}



int main(int argc, char *argv[])
{
    struct ta_attrs ta;
    
    // FILE* filePointer;
    int bufferLength = 1024;
    char word[bufferLength];
    char out_word[bufferLength];

    // filePointer = fopen("message.txt", "r");
    // strcpy(word, "HELLLLLO");

    // fgets(word, bufferLength, filePointer);
    prepare_ta_session(&ta);
    printf("\nType a word:");
    fflush(stdin);
    fgets(word, sizeof(word), stdin);
    send_to_tee(&ta, word, bufferLength, out_word, bufferLength, TA_PLAIN_TEXT);
    send_to_tee(&ta, word, bufferLength, out_word, bufferLength, TA_SHA256);
    printf("%s", word);
	bufferLength = 256;
    char root_id[] = "merkle_root";
    char merkle_root[bufferLength];
    strcpy(merkle_root, hashed);
    printf("%s", merkle_root);
    printf("%s", word);
    char read_data[bufferLength];
    TEEC_Result res;
    
    printf("\nTest on object \"%s\"\n", root_id);
	printf("size: %d", sizeof(read_data));
    if(strcmp(word,"hello\n") == 0 || strcmp(word,"hello") == 0)
	{
        printf("- Create and load object in the TA secure storage\n");

        // memset(merkle_root, 0xA1, sizeof(merkle_root));

        res = write_secure_object(&ta, root_id,
                    merkle_root, sizeof(merkle_root));
        if (res != TEEC_SUCCESS)
            errx(1, "Failed to create an object in the secure storage");
    }
	printf("- Read back the object\n");

	res = read_secure_object(&ta, root_id,
				 read_data, sizeof(read_data));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to read an object from the secure storage");
    printf("%s\n", read_data);


    if(strcmp(word,"bye") == 0 || strcmp(word,"bye\n") == 0){
        printf("- Delete the object\n");

        res = delete_secure_object(&ta, root_id);
        if (res != TEEC_SUCCESS)
           errx(1, "Failed to delete the object: 0x%x", res);
    }
    terminate_tee_session(&ta);
}
