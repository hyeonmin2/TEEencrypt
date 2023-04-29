#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc,char **argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	unsigned int key = 0;
	unsigned int cipherkey = 0;
	int key_size = sizeof(unsigned int);

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = &key;
	op.params[1].tmpref.size = key_size;

	if(strcmp(argv[1],"-e")==0) {
		printf("==Encryption==\n");

		//read plaintext file
		FILE* fp1 = fopen(argv[2], "r");
		fread(plaintext, 1, 64, fp1);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		fclose(fp1);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		//save ciphertext and cipherkey
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		memcpy(&cipherkey, op.params[1].tmpref.buffer, key_size);
		printf("Ciphertext : %s\n", ciphertext);
		printf("Cipherkey : %u\n", cipherkey);
		FILE* fp2 = fopen("enc.txt","w");
		fputs(ciphertext,fp2);
		fprintf(fp2, "%u\n", cipherkey);
		fclose(fp2);
	}
	if(strcmp(argv[1],"-d")==0) {
	
		printf("==Decryption==\n");
	
		//read encrypt file
		char str[100] = {0,};
		FILE* fp3 = fopen(argv[2], "r");
		fread(str, 1, 100, fp3);
		char* ptr = strtok(str,"\n");
		strcpy(ciphertext, ptr);
		ptr = strtok(NULL, "\n");
		cipherkey = atoi(ptr);
		fclose(fp3);
	
		printf("ciphertext: %s, chipherkey: %u\n", ciphertext, cipherkey);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		memcpy(op.params[1].tmpref.buffer, &cipherkey, key_size);
	
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
	
		//save plaintext
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);
		FILE* fp4 = fopen("dec.txt","w");
		fputs(plaintext,fp4);
		fputs("\n",fp4);
		fclose(fp4);
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
