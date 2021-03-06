#include <tee_internal_api.h>
#include <string.h>
#include <tee_api.h>
#include <sha2_impl.h>

//#include <tee_internal_api_extensions.h>

#include <assess.h>

static TEE_Result delete_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;

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

	/*
	 * Check object exists and delete it
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
								   obj_id, obj_id_sz,
								   TEE_DATA_FLAG_ACCESS_READ |
									   TEE_DATA_FLAG_ACCESS_WRITE_META, /* we must be allowed to delete it */
								   &object);
	if (res != TEE_SUCCESS)
	{
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		return res;
	}

	TEE_CloseAndDeletePersistentObject1(object);
	TEE_Free(obj_id);

	return res;
}

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

static TEE_Result read_raw_object(uint32_t param_types, TEE_Param params[4])
{
	DMSG("Reading!");
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;

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

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

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
		return res;
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
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize,
							 &read_bytes);
	DMSG(data);
	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, data, read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize)
	{
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
			 res, read_bytes, object_info.dataSize);
		goto exit;
	}

	/* Return the number of byte effectively filled */
	params[1].memref.size = read_bytes;
exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
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

TEE_Result hash_SHA256(void *session_id, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	static TEE_OperationHandle digest_op = NULL;

	uint32_t algo = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_MEMREF_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	algo = TEE_ALG_SHA256;

	if (digest_op)
		TEE_FreeOperation(digest_op);

	res = TEE_AllocateOperation(&digest_op, algo, TEE_MODE_DIGEST, 0);

	if (res != TEE_SUCCESS)
	{
		EMSG("Error in setting hash function!");
		return res;
	}
	void *in = NULL;
	void *out = NULL;
	uint32_t insz = 0;
	uint32_t outsz = 0;
	uint32_t offset = 0;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	in = (uint8_t *)params[0].memref.buffer;
	insz = params[0].memref.size;
	out = params[1].memref.buffer;
	outsz = params[1].memref.size;

	res = TEE_DigestDoFinal(digest_op, in, insz, out, &outsz);

	return res;
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
	switch (command_id)
	{
	case TA_SHA256:
		hash_SHA256(&session_id, parameters_type, parameters);
		break;
	case TA_PLAIN_TEXT:
		print_passed(&session_id, parameters_type, parameters);
		break;
	case TA_SECURE_STORAGE_CMD_WRITE_RAW:
		return create_raw_object(parameters_type, parameters);
	case TA_SECURE_STORAGE_CMD_READ_RAW:
		return read_raw_object(parameters_type, parameters);
	case TA_SECURE_STORAGE_CMD_DELETE:
		return delete_object(parameters_type, parameters);
	default:
		EMSG("Command ID 0x%x is not supported", command_id);
		return TEE_ERROR_NOT_SUPPORTED;
		// default:
		// 	print_passed(&session_id, parameters_type, parameters);
		// 	break;
	}
	/* Return with a status */
	return TEE_SUCCESS;
}
