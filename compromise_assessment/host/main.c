#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include <assess.h>

struct ta_attrs
{
	TEEC_Context ctx;
	TEEC_Session sess;
};

struct MerkleTree
{
	struct MerkleTree *left;
	struct MerkleTree *right;
	char hash[64];
};

struct MerkleTree *Node(char *hash_value)
{
	// Allocate memory for new node
	struct MerkleTree *node = (struct MerkleTree *)malloc(sizeof(struct MerkleTree));

	// Assign data to this node
	memcpy(node->hash, hash_value, 32);
	node->left = NULL;
	node->right = NULL;
	return (node);
}

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_COMPROMISE_ASSESSMENT_UUID;
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

	switch (res)
	{
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

char hashed[64];

void send_to_tee(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz, uint32_t mode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, mode, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nFAIL\n", res, origin);
	printf("Received from TEE: ");
	fwrite(op.params[1].tmpref.buffer, sizeof(char), 32, stdout);
	fprintf(stdout, "\n");

	char *ret;
	ret = (char *)op.params[1].tmpref.buffer;
	memcpy(hashed, ret, 32);
}

void printTree(struct MerkleTree *node, int d)
{
	if (node == NULL)
		return;
	printf("%d: ", d);
	fwrite(node->hash, sizeof(char), 32, stdout);
	fprintf(stdout, "\n");

	printTree(node->left, d + 1);
	printTree(node->right, d + 1);
}

int main(int argc, char *argv[])
{
	struct ta_attrs ta;

	// FILE* filePointer;
	int bufferLength = 64;
	char word[bufferLength];

	// filePointer = fopen("message.txt", "r");

	// fgets(word, bufferLength, filePointer);
	prepare_ta_session(&ta);
	// printf("\nType a word:");
	// fflush(stdin);
	// fgets(word, sizeof(word), stdin);

	FILE *fp;
	char *line = NULL;
	size_t len_file = 0;
	ssize_t read;

	struct MerkleTree *node[50];

	fp = fopen("files.txt", "r");
	if (fp == NULL)
		return 0;

	struct MerkleTree *root;

	int n = 0;
	FILE *iter;
	char out_word[bufferLength];
	send_to_tee(&ta, word, bufferLength, out_word, bufferLength, TA_PLAIN_TEXT);
	while ((read = getline(&line, &len_file, fp)) != -1)
	{
		int line_len = strlen(line);

		if (line[line_len - 1] == '\n')
			line[line_len - 1] = 0;

		FILE *infile;
		char *buffer;
		long numbytes;

		infile = fopen(line, "r");

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

		char content[7000];

		memcpy(content, buffer, numbytes);
		free(buffer);
		// printf("%s", content);
		send_to_tee(&ta, content, numbytes, out_word, bufferLength, TA_SHA256);
		node[n++] = Node((char *)hashed);
	}
	fclose(fp);

	if (line)
		free(line);

	while (n > 1)
	{
		int m = n / 2;
		int i = 0;
		for (i = 0; i < m; i++)
		{
			char str[128];
			memcpy(str, node[2 * i]->hash, 32);
			for (int j = 0; j < 32; j++)
				str[32 + j] = node[2 * i + 1]->hash[j];
			struct MerkleTree *left = node[2 * i];
			struct MerkleTree *right = node[2 * i + 1];
			send_to_tee(&ta, str, 64, out_word, bufferLength, TA_SHA256);
			node[i] = Node((char *)hashed);
			node[i]->left = left;
			node[i]->right = right;
		}

		if (2 * m < n)
		{
			node[m] = node[2 * m];
			m++;
		}
		n = m;
	}
	root = node[0];

	printf("-----------------------------------------\n");

	// printTree(root, 0);

	char root_id[] = "merkle_root";
	char merkle_root[bufferLength];
	memcpy(merkle_root, root->hash, 32);

	printf("ROOT: ");
	fwrite(merkle_root, sizeof(char), 32, stdout);
	fprintf(stdout, "\n");

	// printf("ROOT: %d\n", strlen(merkle_root));
	// printf("%s", word);
	char read_data[bufferLength];
	TEEC_Result res;

	printf("\nTest on object \"%s\"\n", root_id);
	if (argc >= 2 && strcmp(argv[1], "0") == 0)
	{
		printf("- Create and load object in the TA secure storage\n");

		res = write_secure_object(&ta, root_id,
								  merkle_root, 32);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to create an object in the secure storage");
	}

	if (argc >= 2 && strcmp(argv[1], "1") == 0)
	{
		printf("- Read back previously stored hash tree root value: \n");

		res = read_secure_object(&ta, root_id,
								 read_data, 32);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to read an object from the secure storage");

		printf("%s\n", read_data);

		if (memcmp(merkle_root, read_data, 32))
			errx(1, "Compromise detected!");

		printf("Root matches the trusted storage!\n");
	}
	if (argc >= 2 && strcmp(argv[1], "2") == 0)
	{
		printf("Clear the secure storage\n");

		res = delete_secure_object(&ta, root_id);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to delete the object: 0x%x", res);
	}
	terminate_tee_session(&ta);
	return 0;
}