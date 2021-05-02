#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <tee_api.h>

#include <authenticated_encryption_ta.h>
// #include <aes.h>
#define AES128_KEY_BIT_SIZE 128
#define AES128_KEY_BYTE_SIZE (AES128_KEY_BIT_SIZE / 8)

/*
 * Ciphering context: each opened session relates to a cipehring operation.
 * - configure the AES flavour from a command.
 * - load key from a command (here the key is provided by the REE)
 * - reset init vector (here IV is provided by the REE)
 * - cipher a buffer frame (here input and output buffers are non-secure)
 */
static TEE_Result create_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	uint32_t obj_data_flag;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);
	DMSG(obj_id);
	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[1].memref.buffer, data_sz);

	/*
	 * Create object in secure storage and fill with data
	 */
	obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		  /* we can later read the oject */
					TEE_DATA_FLAG_ACCESS_WRITE |	  /* we can later write into the object */
					TEE_DATA_FLAG_ACCESS_WRITE_META | /* we can later destroy or rename the object */
					TEE_DATA_FLAG_OVERWRITE;		  /* destroy existing object of same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
									 obj_id, obj_id_sz,
									 obj_data_flag,
									 TEE_HANDLE_NULL,
									 NULL, 0, /* we may not fill it right now */
									 &object);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}
	DMSG(data);
	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	}
	else
	{
		TEE_CloseObject(object);
	}
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

// static char *read_raw_object(uint32_t param_types, TEE_Param params[4])
static char *read_raw_object(char *obj_id, size_t obj_id_sz)
{
	DMSG("Reading!");
	// const uint32_t exp_param_types =
	// 	TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
	// 					TEE_PARAM_TYPE_MEMREF_OUTPUT,
	// 					TEE_PARAM_TYPE_NONE,
	// 					TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	// char *obj_id;
	// size_t obj_id_sz;
	char *data;
	size_t data_sz;

	/*
	 * Safely get the invocation parameters
	 */
	// if (param_types != exp_param_types)
	// 	return "FAIL!";
	// return TEE_ERROR_BAD_PARAMETERS;

	// obj_id_sz = params[0].memref.size;
	// obj_id = TEE_Malloc(obj_id_sz, 0);
	// if (!obj_id)
	// 	return "FAIL!";
	// return TEE_ERROR_OUT_OF_MEMORY;

	// TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	// data_sz = params[1].memref.size;
	data_sz = 16;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return "FAIL!";
	// return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
								   obj_id, obj_id_sz,
								   TEE_DATA_FLAG_ACCESS_READ |
									   TEE_DATA_FLAG_SHARE_READ,
								   &object);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return "FAIL!";
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}

	if (object_info.dataSize > data_sz)
	{
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		// params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize,
							 &read_bytes);
	DMSG(data);
	if (res == TEE_SUCCESS)
		return data;
	// TEE_MemMove(params[1].memref.buffer, data, read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize)
	{
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
			 res, read_bytes, object_info.dataSize);
		goto exit;
	}

	/* Return the number of byte effectively filled */
	// params[1].memref.size = read_bytes;
exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return "FAIL!";
	// return res;
}

struct aes_cipher
{
	uint32_t algo;				   /* AES flavour */
	uint32_t mode;				   /* Encode or decode */
	uint32_t key_size;			   /* AES key size in byte */
	TEE_OperationHandle op_handle; /* AES ciphering operation */
	TEE_ObjectHandle key_handle;   /* transient object to load the key */
};
/*
 * Few routines to convert IDs from TA API into IDs from OP-TEE.
 */

static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
{
	switch (param)
	{
	case TA_AES_ALGO_CTR:
		*algo = TEE_ALG_AES_CTR;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
{
	switch (param)
	{
	case AES128_KEY_BYTE_SIZE:
		*key_size = param;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid key size %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
{
	switch (param)
	{
	case TA_AES_MODE_ENCODE:
		*mode = TEE_MODE_ENCRYPT;
		return TEE_SUCCESS;
	case TA_AES_MODE_DECODE:
		*mode = TEE_MODE_DECRYPT;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Process command TA_AES_CMD_PREPARE. API in aes_ta.h
 *
 * Allocate resources required for the ciphering operation.
 * During ciphering operation, when expect client can:
 * - update the key materials (provided by client)
 * - reset the initial vector (provided by client)
 * - cipher an input buffer into an output buffer (provided by client)
 */
static TEE_Result alloc_resources(void *session, uint32_t param_types,
								  TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	/* Get ciphering context from session ID */
	DMSG("Session %p: get ciphering resources", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ta2tee_algo_id(params[0].value.a, &sess->algo);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_key_size(params[1].value.a, &sess->key_size);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_mode_id(params[2].value.a, &sess->mode);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * Ready to allocate the resources which are:
	 * - an operation handle, for an AES ciphering of given configuration
	 * - a transient object that will be use to load the key materials
	 *   into the AES ciphering operation.
	 */

	/* Free potential previous operation */
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&sess->op_handle,
								sess->algo,
								sess->mode,
								sess->key_size * 8);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to allocate operation");
		sess->op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Free potential previous transient object */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
									  sess->key_size * 8,
									  &sess->key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to allocate transient object");
		sess->key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/*
	 * When loading a key in the cipher session, set_aes_key()
	 * will reset the operation and load a key. But we cannot
	 * reset and operation that has no key yet (GPD TEE Internal
	 * Core API Specification – Public Release v1.1.1, section
	 * 6.2.5 TEE_ResetOperation). In consequence, we will load a
	 * dummy key in the operation so that operation can be reset
	 * when updating the key.
	 */
	key = TEE_Malloc(sess->key_size, 0);
	if (!key)
	{
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	return res;

err:
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	sess->op_handle = TEE_HANDLE_NULL;

	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	sess->key_handle = TEE_HANDLE_NULL;

	return res;
}

/*
 * Process command TA_AES_CMD_SET_KEY. API in aes_ta.h
 */
static TEE_Result set_aes_key(void *session, uint32_t param_types,
							  TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;
	uint32_t key_sz;
	char *key;

	/* Get ciphering context from session ID */
	DMSG("Session %p: load key material", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// key = params[0].memref.buffer;
	// key_sz = params[0].memref.size;
	strcpy(key, read_raw_object("aeskey", 6));
	if (strlen(key) != 16)
		return TEE_ERROR_BAD_PARAMETERS;
	key_sz = 16;
	if (key_sz != sess->key_size)
	{
		EMSG("Wrong key size %" PRIu32 ", expect %" PRIu32 " bytes",
			 key_sz, sess->key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Load the key material into the configured operation
	 * - create a secret key attribute with the key material
	 *   TEE_InitRefAttribute()
	 * - reset transient object and load attribute data
	 *   TEE_ResetTransientObject()
	 *   TEE_PopulateTransientObject()
	 * - load the key (transient object) into the ciphering operation
	 *   TEE_SetOperationKey()
	 *
	 * TEE_SetOperationKey() requires operation to be in "initial state".
	 * We can use TEE_ResetOperation() to reset the operation but this
	 * API cannot be used on operation with key(s) not yet set. Hence,
	 * when allocating the operation handle, we load a dummy key.
	 * Thus, set_key sequence always reset then set key on operation.
	 */

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_sz);

	TEE_ResetTransientObject(sess->key_handle);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS)
	{
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}

	return res;
}

/*
 * Process command TA_AES_CMD_SET_IV. API in aes_ta.h
 */
static TEE_Result reset_aes_iv(void *session, uint32_t param_types,
							   TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
	size_t iv_sz;
	char *iv;

	/* Get ciphering context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	iv = params[0].memref.buffer;
	iv_sz = params[0].memref.size;

	/*
	 * Init cipher operation with the initialization vector.
	 */
	TEE_CipherInit(sess->op_handle, iv, iv_sz);

	return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_CIPHER. API in aes_ta.h
 */
static TEE_Result cipher_buffer(void *session, uint32_t param_types,
								TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: cipher buffer", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size < params[0].memref.size)
	{
		EMSG("Bad sizes: in %d, out %d", params[0].memref.size,
			 params[1].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (sess->op_handle == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Process ciphering operation on provided buffers
	 */
	return TEE_CipherUpdate(sess->op_handle,
							params[0].memref.buffer, params[0].memref.size,
							params[1].memref.buffer, &params[1].memref.size);
}

TEE_Result check_params(uint32_t param_types)
{
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

TEE_Result print_passed(void *session, uint32_t param_types, TEE_Param params[4])
{
	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	// void *cipher = params[1].memref.buffer;
	// size_t cipher_len = params[1].memref.size;

	DMSG("\nReceived Data: %s\n", (char *)plain_txt);

	char ret_arg[] = "Working";
	memcpy(params[1].memref.buffer, ret_arg, 8);

	return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
									TEE_Param __maybe_unused params[4],
									void __maybe_unused **session)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Hello World!\n");

	struct aes_cipher *sess;

	/*
	 * Allocate and init ciphering materials for the session.
	 * The address of the structure is used as session ID for
	 * the client.
	 */
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct aes_cipher *)session;

	/* Release the session resources */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);

	IMSG("Goodbye!\n");
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
									  uint32_t command_id,
									  uint32_t parameters_type,
									  TEE_Param params[4])
{
	// (void)&sess_ctx; /* Unused parameter */
	switch (command_id)
	{
	case TA_PLAIN_TEXT:
		return print_passed(&session_id, parameters_type, params);
	case TA_AES_CMD_PREPARE:
		return alloc_resources(session_id, parameters_type, params);
	case TA_AES_CMD_SET_KEY:
		return set_aes_key(session_id, parameters_type, params);
	case TA_AES_CMD_SET_IV:
		return reset_aes_iv(session_id, parameters_type, params);
	case TA_AES_CMD_CIPHER:
		return cipher_buffer(session_id, parameters_type, params);
	case TA_SECURE_STORAGE_CMD_WRITE_RAW:
		return create_raw_object(parameters_type, params);
	// case TA_SECURE_STORAGE_CMD_READ_RAW:
	// return read_raw_object(parameters_type, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}
