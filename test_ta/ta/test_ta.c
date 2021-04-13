#include <tee_internal_api.h>
#include <string.h>
#include <tee_api.h>

#include <sha2_impl.h>

//#include <tee_internal_api_extensions.h>

#include <test_ta.h>

TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}


static uint32_t sha256_digest(char *source)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_OperationHandle digest_handler = (TEE_OperationHandle)NULL;
	void *rand_msg = NULL;
	
	char hash[64] = {0};
	
	uint32_t rand_msg_len = 1024;
	uint32_t hash_len = 64;
	uint32_t fn_ret = 1; /* Initialized error return */
	rand_msg = TEE_Malloc(rand_msg_len, 0);
	
	if (rand_msg == NULL) {
		DMSG("Out of memory");
		goto err;
	}
	memcpy(rand_msg, source, 1024); 

	ret = TEE_AllocateOperation(&digest_handler, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		DMSG("Cant alloc first handler");
		goto err;
	}

	TEE_DigestUpdate(digest_handler, rand_msg, rand_msg_len);

	ret = TEE_DigestDoFinal(digest_handler, NULL, 0, hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		DMSG("Failed final first");
		goto err;
	}

	DMSG(rand_msg);
	DMSG(hash);


	fn_ret = 0;

err:
	TEE_FreeOperation(digest_handler);
	// TEE_FreeOperation(digest_handler_2);
	TEE_Free(rand_msg);
	// TEE_Free(rand_msg_2);

	if (fn_ret == 0)
		DMSG("-");

	return fn_ret;
}

int mystrlen(char *p)
{
    int c=0;
    while(*p!='\0')
    {
        c++;
        *p++;
    }
    return(c);
}

TEE_Result ta_entry_sha256(uint32_t param_types, TEE_Param params[4])
{
	/*
	 * It is expected that memRef[0] is input buffer and memRef[1] is
	 * output buffer.
	 */
	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < SHA256_DIGEST_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	unsigned char *digest;
	unsigned char *plain_txt = params[0].memref.buffer;
	
	sha256((unsigned char *)plain_txt,
	       mystrlen(plain_txt),
	       (unsigned char *)digest);

	// sha256("hello", 5, (unsigned char *)digest);


	// DMSG(params[1].memref.buffer);

	DMSG(digest);
	
	memcpy(params[1].memref.buffer, digest, 64);
	return TEE_SUCCESS;
}


// static int calc_digest(void *msg,
// 		       uint32_t msg_len,
// 		       void *hash,
// 		       uint32_t *hash_len)
// {
// 	TEE_OperationHandle operation = (TEE_OperationHandle)NULL;
// 	TEE_Result ret;

// 	ret = TEE_AllocateOperation(&operation, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
// 	if (ret != TEE_SUCCESS) {
// 		DMSG("Failed allocate digest operation");
// 		return 1;
// 	}
// 	DMSG("WORKING....");
// 	DMSG(msg);
// 	ret = TEE_DigestDoFinal(operation, msg, msg_len, hash, hash_len);
// 	DMSG("WORKING....");

// 	TEE_FreeOperation(operation);
// 	DMSG("WORKING....");

// 	if (ret != TEE_SUCCESS) {
// 		DMSG("Final failed");
// 		return 1;
// 	}
// 	DMSG(hash);
// 	return 0;
// }

TEE_Result hash_SHA256(void *session_id, uint32_t param_types, TEE_Param params[4]){
	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("ENTERED SHA256");
	// TEE_Result res;
	void *plain_txt = params[0].memref.buffer;
	// DMSG(plain_txt);
	// uint32_t plain_len = params[0].memref.size;
	// DMSG(plain_len);
	// void *hash = params[1].memref.buffer;
	// uint32_t hash_len = params[1].memref.size;
	
	ta_entry_sha256(param_types, params);
	// sha256_digest(plain_txt);
	
	
	// calc_digest("hello", 5, hash, hash_len);
	// DMSG(hash);
// 	TEE_OperationHandle l_OperationHandle;
// 	res = TEE_AllocateOperation(&l_OperationHandle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
//     if(res != TEE_SUCCESS)
//     {
//         DMSG("Allocate SHA operation handle fail\n");
// 		return TEE_ERROR_BAD_PARAMETERS;
//     }
// 	DMSG("WORKING 1!");


//     TEE_DigestUpdate(l_OperationHandle, plain_txt, plain_len);
// 	DMSG("WORKING 2!");

//     /**4) Do the final sha operation */
// 	res = TEE_DigestDoFinal(l_OperationHandle, NULL, 0, hash, hash_len);
// 	DMSG("WORKING 3!");

// 	if(res != TEE_SUCCESS)
//     {
//         DMSG("Do the final sha operation fail\n");
// 		return TEE_ERROR_BAD_PARAMETERS;
//     }
// 	DMSG("The out put length is :%d\n", *hash_len);
//     // DMSG(*hash);

// 	return TEE_SUCCESS;

}


TEE_Result print_passed(void *session, uint32_t param_types, TEE_Param params[4]) {
	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	// void *cipher = params[1].memref.buffer;
	// size_t cipher_len = params[1].memref.size;	

	DMSG("\nReceived Data: %s\n", (char *) plain_txt);


	char ret_arg[] = "Bye Bye";
	memcpy(params[1].memref.buffer, ret_arg, 8);

	return TEE_SUCCESS;
}


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}


TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4])
{
    /* Decode the command and process execution of the target service */
	switch(command_id){
		case TA_SHA256:
			hash_SHA256(&session_id, parameters_type, parameters);
			break;
		case TA_PLAIN_TEXT:
			print_passed(&session_id, parameters_type, parameters);
			break;
		default: 
			print_passed(&session_id, parameters_type, parameters);
			break;
	}
    /* Return with a status */
    return TEE_SUCCESS;
}
