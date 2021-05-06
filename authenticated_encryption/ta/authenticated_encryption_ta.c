#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <tee_api.h>
#include <sha2_impl.h>

#include <authenticated_encryption_ta.h>

#define AES128_KEY_BIT_SIZE 128
#define AES128_KEY_BYTE_SIZE (AES128_KEY_BIT_SIZE / 8)
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

// uint8_t modulus[] = "\x80\x55\x45\x4b\x27\xd0\x55\x80\x7a\xc9\x12\x6b\x8e\x7b\xb2\x70\x01\x5f\x63\x0a\xb5\x5a\x74\xc9\x26\x88\x30\xbe\x10\x4d\xd6\x6c\x42\x5a\x9c\xe2\x94\x45\x52\xdb\xa0\x82\xe6\x2d\xbd\x7c\x84\x53\xd3\x32\x6e\xf2\x1e\xae\x1d\x5c\x10\x29\x45\xfa\xb8\x5f\xb3\x71\xe8\x76\x0d\x52\xc1\x2e\x68\xc7\x2a\x3a\x1d\xef\x7e\xe2\xd2\x87\xc2\xea\xb4\x91\xb4\xbe\x6e\xf1\x26\x68\xbd\x0a\x14\xb8\xdc\x5a\x60\xbd\x50\xbd\xa4\x87\x51\xaa\x99\x32\x2f\xe3\x1f\x76\x8e\x6f\xa1\x8f\xad\xf9\xf6\x98\xaa\x1a\xc6\x3b\x8f\x91\xc5\x89\xda\xfd";

// uint8_t public_exp[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";

uint8_t private_exp[] = "\x67\xa2\xf5\x13\xad\x72\x5c\x2a\x26\x7e\x4c\xc6\xd9\x48\xe1\x9f\xfc\x2b\xc8\xf2\xf3\xe3\xb9\xde\x5b\xa4\xae\x20\x3f\x50\x6c\xb1\xfe\x9f\xe8\x84\x3e\x13\x01\xc7\xe5\x86\xf0\x55\xcd\xe9\x49\x7f\xdc\x55\xa5\x2d\x18\x43\xa9\xe8\x18\x11\x0c\xb7\x5d\xbf\xc3\x4c\x32\x3f\xc9\x85\x03\xd7\xa8\x47\xd4\xec\xd3\x37\xbb\x8a\xfc\xf8\xb8\x79\x0f\x36\x19\xbf\xbb\xf7\xd2\x57\x7d\x52\x8f\x57\x77\x84\x0b\xb8\x1f\xbc\x5f\xa6\x46\x1b\xf9\x4b\xaa\xf1\x5b\xc1\xe1\xb6\xdc\x16\x96\x2e\x91\xa3\x06\x1e\x20\xbf\xd0\x3a\xd6\x6f\x3d\xcd";
uint8_t target_private_exp[] = "\x67\x6b\x2f\xb0\x4c\xae\xbe\x33\x11\x27\xc1\x81\x86\x3b\xb3\xd3\x90\xc6\x77\xfd\x70\xd4\x03\xe8\xa7\xe4\x55\x05\x62\xb0\x75\xcd\xb3\xb8\x77\x85\x0a\xef\x71\x7d\xa6\xce\x97\x75\xa9\xe2\x11\x79\x2d\x2f\x73\xae\x24\x7b\x7c\x18\xce\x80\x0f\xbd\xc1\xd6\x3a\x6d\xef\xac\x6d\x83\xe8\xe3\xca\x01\x42\x17\xc5\x3e\x94\xde\xf0\xd2\xcf\xbd\xb8\x29\xd3\x5b\xe0\xad\x46\x1c\x9e\xa7\x7e\xe0\x0c\x55\xcb\xdc\x2d\x5b\x2c\x3b\xdd\xfb\xa5\x3e\x4c\xd9\x52\x90\x3a\xee\xc3\x44\x74\x6f\x3d\x44\xdf\x3c\x76\x9a\x48\x71\xb4\xe4\x16\xd1";

int mystrlen(char *p)
{
	int c = 0;
	while (*p != '\0')
	{
		c++;
		*p++;
	}
	return (c);
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
						TEE_PARAM_TYPE_NONE))
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < SHA256_DIGEST_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	unsigned char *digest;
	unsigned char *plain_txt = params[0].memref.buffer;

	sha256((unsigned char *)plain_txt,
		   RSA_CIPHER_LEN_1024,
		   (unsigned char *)digest);

	DMSG(digest);
	DMSG("okay!");

	memcpy(params[1].memref.buffer, digest, 32);
	DMSG("okay!");
	return TEE_SUCCESS;
}
TEE_Result hash_SHA256(void *session_id, uint32_t param_types, TEE_Param params[4])
{
	// if (check_params(param_types) != TEE_SUCCESS)
	// 	return TEE_ERROR_BAD_PARAMETERS;

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
static char *read_raw_object(char *obj_id, size_t obj_id_sz, size_t data_sz)
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
	// data_sz = 16;
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
	DMSG("READ!");
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

//////////////////////////////////////////////////////////////////////////////////////

struct rsa_session
{
	TEE_OperationHandle op_handle; /* RSA operation */
	TEE_ObjectHandle key_handle;   /* Key handle */
};

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation key already set. ==========\n");

	return ret;
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

TEE_Result RSA_set_key_pair(void *session, uint32_t param_types,
							TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	char *pub_key, *mod, *priv_key;
	uint32_t key_sz, mod_sz;
	pub_key = params[0].memref.buffer;
	key_sz = params[0].memref.size;
	mod = params[1].memref.buffer;
	mod_sz = params[1].memref.size;

	if (params[2].memref.size == 2)
		priv_key = (char *)private_exp;
	else if (params[2].memref.size == 3)
		priv_key = (char *)target_private_exp;
	else if (params[2].memref.size == 4)
	{
		priv_key = pub_key;
		pub_key = (char *)private_exp;
	}
	else
	{
		priv_key = pub_key;
		pub_key = (char *)target_private_exp;
	}
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	// ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	// if (ret != TEE_SUCCESS)
	// {
	// 	EMSG("\nGenerate key failure: 0x%x\n", ret);
	// 	return ret;
	// }

	TEE_Attribute rsa_attrs[3];

	/* Modulo */
	rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
	rsa_attrs[0].content.ref.buffer = mod;
	rsa_attrs[0].content.ref.length = 128;

	/* Public exp */
	rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	rsa_attrs[1].content.ref.buffer = pub_key;
	rsa_attrs[1].content.ref.length = 128;

	/* Private exp */
	rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
	rsa_attrs[2].content.ref.buffer = priv_key;
	rsa_attrs[2].content.ref.length = 128;

	ret = TEE_PopulateTransientObject(sess->key_handle, (TEE_Attribute *)&rsa_attrs, 3);
	if (ret != TEE_SUCCESS)
	{
		DMSG("RSA key population failed");
		return ret;
	}

	DMSG("\n========== Keys generated. ==========\n");

	/* Export private key */
	TEE_Result res;
	uint8_t modu[258];
	uint32_t modulusLen = 128;
	uint8_t pubexp[258];
	uint32_t pubexpLen = 128;
	uint8_t pvtexp[258];
	uint32_t pvtexpLen = sizeof(private_exp);
	res = TEE_GetObjectBufferAttribute(sess->key_handle, TEE_ATTR_RSA_MODULUS, (void *)modu, &modulusLen);
	if (res != TEE_SUCCESS)
	{
		DMSG("TEE_GetObjectBufferAttribute() failed res=0x%X\n", (int)res);
		return res;
	}
	res = TEE_GetObjectBufferAttribute(sess->key_handle, TEE_ATTR_RSA_PUBLIC_EXPONENT, (void *)pubexp, &pubexpLen);
	if (res != TEE_SUCCESS)
	{
		DMSG("TEE_GetObjectBufferAttribute() failed res=0x%X\n", (int)res);
		return res;
	}
	res = TEE_GetObjectBufferAttribute(sess->key_handle, TEE_ATTR_RSA_PRIVATE_EXPONENT, (void *)pvtexp, &pvtexpLen);
	if (res != TEE_SUCCESS)
	{
		DMSG("TEE_GetObjectBufferAttribute() failed res=0x%X\n", (int)res);
		return res;
	}
	DMSG("RSA_MODULUS %d bytes\n", (int)modulusLen);
	DMSG("RSA_PUBLIC_EXPONENT %d bytes\n", (int)pubexpLen);
	DMSG("RSA_PRIVATE_EXPONENT %d bytes\n", (int)pvtexpLen);
	DMSG((char *)modu);
	DMSG((char *)pubexp);
	DMSG((char *)pvtexp);

	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *)plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
								plain_txt, plain_len, cipher, &cipher_len);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *)cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4])
{
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[1].memref.buffer;
	size_t plain_len = params[1].memref.size;
	void *cipher = params[0].memref.buffer;
	size_t cipher_len = params[0].memref.size;
	// void *cipher;
	// size_t cipher_len = RSA_CIPHER_LEN_1024;
	// cipher = ((void *)read_raw_object("ctext", 5, RSA_CIPHER_LEN_1024));
	DMSG("\n========== Preparing decryption operation ==========\n");
	// DMSG("\nData to decrypt: %s\n", (char *)cipher);
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char *)cipher);

	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
								cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char *)plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}
//////////////////////////////////////////////////////////////////////////////////////

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
	strcpy(key, read_raw_object("aeskey", 6, 16));
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
// }
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

// TEE_Result check_params(uint32_t param_types)
// {
// 	const uint32_t exp_param_types =
// 		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
// 						TEE_PARAM_TYPE_MEMREF_OUTPUT,
// 						TEE_PARAM_TYPE_NONE,
// 						TEE_PARAM_TYPE_NONE);

// 	/* Safely get the invocation parameters */
// 	if (param_types != exp_param_types)
// 		return TEE_ERROR_BAD_PARAMETERS;
// 	return TEE_SUCCESS;

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
	case TA_RSA_CMD_GENKEYS:
		return RSA_set_key_pair(session_id, parameters_type, params);
	case TA_RSA_CMD_ENCRYPT:
		return RSA_encrypt(session_id, parameters_type, params);
	case TA_RSA_CMD_DECRYPT:
		return RSA_decrypt(session_id, parameters_type, params);
		// case TA_SHA256:
		// ta_entry_sha256(parameters_type, params);
		// break;
	case TA_SHA256:
		hash_SHA256(&session_id, parameters_type, params);
		break;
	// case TA_SECURE_STORAGE_CMD_READ_RAW:
	// return read_raw_object(parameters_type, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}
