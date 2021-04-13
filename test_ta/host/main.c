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
    send_to_tee(&ta, word, bufferLength, out_word, bufferLength, TA_SHA256);
    printf("%s", word);
    send_to_tee(&ta, word, bufferLength, out_word, bufferLength, TA_SHA256);
    printf("%s", word);
    send_to_tee(&ta, word, bufferLength, out_word, bufferLength, TA_SHA256);
    printf("%s", word);
    terminate_tee_session(&ta);
}