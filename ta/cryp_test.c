/*
 * Copyright (c) 2016, Amlogic.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define GCM_DEBUG IMSG
#define GCM_ERROR EMSG
/*
 * AES-GCM vectors from the reviced "The Galois/Counter Mode of Operation
 * (GCM)" 2005-05-31 spec
 */

/*
 * Test case 1
 *              K 00000000000000000000000000000000
 *              P
 *             IV 000000000000000000000000
 *              H 66e94bd4ef8a2c3b884cfa59ca342b2e
 *             Y0 00000000000000000000000000000001
 *       E(K, Y0) 58e2fccefa7e3061367f1d57a4e7455a
 * len(A)||len(C) 00000000000000000000000000000000
 *  GHASH(H, A, C) 00000000000000000000000000000000
 *              C
 *              T 58e2fccefa7e3061367f1d57a4e7455a
 */
static const uint8_t ae_data_aes_gcm_vect1_key[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t ae_data_aes_gcm_vect1_nonce[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};
#define ae_data_aes_gcm_vect1_aad NULL
#define ae_data_aes_gcm_vect1_ptx NULL
#define ae_data_aes_gcm_vect1_ctx NULL
static const uint8_t ae_data_aes_gcm_vect1_tag[] = {
	0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
	0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
};

/*
 * Test case 4
 *              K feffe9928665731c6d6a8f9467308308
 *              P d9313225f88406e5a55909c5aff5269a
 *                86a7a9531534f7da2e4c303d8a318a72
 *                1c3c0c95956809532fcf0e2449a6b525
 *                b16aedf5aa0de657ba637b39
 *              A feedfacedeadbeeffeedfacedeadbeef
 *                abaddad2
 *             IV cafebabefacedbaddecaf888
 *              H b83b533708bf535d0aa6e52980d53b78
 *             Y0 cafebabefacedbaddecaf88800000001
 *       E(K, Y0) 3247184b3c4f69a44dbcd22887bbb418
 *             X1 ed56aaf8a72d67049fdb9228edba1322
 *             X2 cd47221ccef0554ee4bb044c88150352
 *             Y1 cafebabefacedbaddecaf88800000002
 *       E(K, Y1) 9bb22ce7d9f372c1ee2b28722b25f206
 *             Y2 cafebabefacedbaddecaf88800000003
 *       E(K, Y2) 650d887c3936533a1b8d4e1ea39d2b5c
 *             Y3 cafebabefacedbaddecaf88800000004
 *       E(K, Y3) 3de91827c10e9a4f5240647ee5221f20
 *             Y4 cafebabefacedbaddecaf88800000005
 *       E(K, Y4) aac9e6ccc0074ac0873b9ba85d908bd0
 *             X3 54f5e1b2b5a8f9525c23924751a3ca51
 *             X4 324f585c6ffc1359ab371565d6c45f93
 *             X5 ca7dd446af4aa70cc3c0cd5abba6aa1c
 *             X6 1590df9b2eb6768289e57d56274c8570
 * len(A)||len(C) 00000000000000a000000000000001e0
 *  GHASH(H, A, C) 698e57f70e6ecc7fd9463b7260a9ae5f
 *              C 42831ec2217774244b7221b784d0d49c
 *                e3aa212f2c02a4e035c17e2329aca12e
 *                21d514b25466931c7d8f6a5aac84aa05
 *                1ba30b396a0aac973d58e091
 *              T 5bc94fbc3221a5db94fae95ae7121a47
 */

static const uint8_t ae_data_aes_gcm_vect4_key[] = {
	0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static const uint8_t ae_data_aes_gcm_vect4_nonce[] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
	0xde, 0xca, 0xf8, 0x88
};
static const uint8_t ae_data_aes_gcm_vect4_aad[] = {
	0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	0xab, 0xad, 0xda, 0xd2
};
static const uint8_t ae_data_aes_gcm_vect4_ptx[] = {
	0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
	0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
	0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
	0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
	0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
	0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
	0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
	0xba, 0x63, 0x7b, 0x39
};
static const uint8_t ae_data_aes_gcm_vect4_ctx[] = {
	0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
	0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
	0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
	0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
	0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
	0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
	0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
	0x3d, 0x58, 0xe0, 0x91
};
static const uint8_t ae_data_aes_gcm_vect4_tag[] = {
	0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
	0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

#if 0
struct aes_gcm_test_s {
    const uint8_t key[32];
    const uint32_t key_len;
    const uint8_t ptx[128];
    const uint32_t ptx_len;
    const uint8_t aad[128];
    const uint32_t aad_len;
    const uint8_t iv[128];
    const uint32_t iv_len;
    const uint8_t ctx[128];
    const uint32_t ctx_len;
    const uint8_t tag[16];
    const uint32_t tag_len;
};

static struct aes_gcm_test_s test_data2 = {
   /* key */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
   16,

   /* PT */
   { 0xa2, 0xaa, 0xb3, 0xad, 0x8b, 0x17, 0xac, 0xdd,
     0xa2, 0x88, 0x42, 0x6c, 0xd7, 0xc4, 0x29, 0xb7,
     0xca, 0x86, 0xb7, 0xac, 0xa0, 0x58, 0x09, 0xc7,
     0x0c, 0xe8, 0x2d, 0xb2, 0x57, 0x11, 0xcb, 0x53,
     0x02, 0xeb, 0x27, 0x43, 0xb0, 0x36, 0xf3, 0xd7,
     0x50, 0xd6, 0xcf, 0x0d, 0xc0, 0xac, 0xb9, 0x29,
     0x50, 0xd5, 0x46, 0xdb, 0x30, 0x8f, 0x93, 0xb4,
     0xff, 0x24, 0x4a, 0xfa, 0x9d, 0xc7, 0x2b, 0xcd,
     0x75, 0x8d, 0x2c },
   67,

   /* ADATA */
   { 0x68, 0x8e, 0x1a, 0xa9, 0x84, 0xde, 0x92, 0x6d,
     0xc7, 0xb4, 0xc4, 0x7f, 0x44 },
   13,

   /* IV */
   { 0xb7, 0x21, 0x38, 0xb5, 0xa0, 0x5f, 0xf5, 0x07,
     0x0e, 0x8c, 0xd9, 0x41, 0x83, 0xf7, 0x61, 0xd8 },
   16,

   /* CT */
   { 0xcb, 0xc8, 0xd2, 0xf1, 0x54, 0x81, 0xa4, 0xcc,
     0x7d, 0xd1, 0xe1, 0x9a, 0xaa, 0x83, 0xde, 0x56,
     0x78, 0x48, 0x3e, 0xc3, 0x59, 0xae, 0x7d, 0xec,
     0x2a, 0xb8, 0xd5, 0x34, 0xe0, 0x90, 0x6f, 0x4b,
     0x46, 0x63, 0xfa, 0xff, 0x58, 0xa8, 0xb2, 0xd7,
     0x33, 0xb8, 0x45, 0xee, 0xf7, 0xc9, 0xb3, 0x31,
     0xe9, 0xe1, 0x0e, 0xb2, 0x61, 0x2c, 0x99, 0x5f,
     0xeb, 0x1a, 0xc1, 0x5a, 0x62, 0x86, 0xcc, 0xe8,
     0xb2, 0x97, 0xa8 },
   67,

   /* TAG */
   { 0x8d, 0x2d, 0x2a, 0x93, 0x72, 0x62, 0x6f, 0x6b,
     0xee, 0x85, 0x80, 0x27, 0x6a, 0x63, 0x66, 0xbf },
   16,
};
#endif

static const uint8_t ae_data_aes_gcm_vect2_key[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t ae_data_aes_gcm_vect2_nonce[] = {
	0xb7, 0x21, 0x38, 0xb5, 0xa0, 0x5f, 0xf5, 0x07,
	0x0e, 0x8c, 0xd9, 0x41, 0x83, 0xf7, 0x61, 0xd8
};
static const uint8_t ae_data_aes_gcm_vect2_aad[] = {
	0x68, 0x8e, 0x1a, 0xa9, 0x84, 0xde, 0x92, 0x6d,
	0xc7, 0xb4, 0xc4, 0x7f, 0x44
};
static const uint8_t ae_data_aes_gcm_vect2_ptx[] = {
	0xa2, 0xaa, 0xb3, 0xad, 0x8b, 0x17, 0xac, 0xdd,
	0xa2, 0x88, 0x42, 0x6c, 0xd7, 0xc4, 0x29, 0xb7,
	0xca, 0x86, 0xb7, 0xac, 0xa0, 0x58, 0x09, 0xc7,
	0x0c, 0xe8, 0x2d, 0xb2, 0x57, 0x11, 0xcb, 0x53,
	0x02, 0xeb, 0x27, 0x43, 0xb0, 0x36, 0xf3, 0xd7,
	0x50, 0xd6, 0xcf, 0x0d, 0xc0, 0xac, 0xb9, 0x29,
	0x50, 0xd5, 0x46, 0xdb, 0x30, 0x8f, 0x93, 0xb4,
	0xff, 0x24, 0x4a, 0xfa, 0x9d, 0xc7, 0x2b, 0xcd,
	0x75, 0x8d, 0x2c
};
static const uint8_t ae_data_aes_gcm_vect2_ctx[] = {
	0xcb, 0xc8, 0xd2, 0xf1, 0x54, 0x81, 0xa4, 0xcc,
	0x7d, 0xd1, 0xe1, 0x9a, 0xaa, 0x83, 0xde, 0x56,
	0x78, 0x48, 0x3e, 0xc3, 0x59, 0xae, 0x7d, 0xec,
	0x2a, 0xb8, 0xd5, 0x34, 0xe0, 0x90, 0x6f, 0x4b,
	0x46, 0x63, 0xfa, 0xff, 0x58, 0xa8, 0xb2, 0xd7,
	0x33, 0xb8, 0x45, 0xee, 0xf7, 0xc9, 0xb3, 0x31,
	0xe9, 0xe1, 0x0e, 0xb2, 0x61, 0x2c, 0x99, 0x5f,
	0xeb, 0x1a, 0xc1, 0x5a, 0x62, 0x86, 0xcc, 0xe8,
	0xb2, 0x97, 0xa8
};
static const uint8_t ae_data_aes_gcm_vect2_tag[] = {
	0x8d, 0x2d, 0x2a, 0x93, 0x72, 0x62, 0x6f, 0x6b,
	0xee, 0x85, 0x80, 0x27, 0x6a, 0x63, 0x66, 0xbf
};

struct gcm_data_s {
	uint32_t key_len;
	uint32_t iv_len;
	uint32_t aad_len;
	uint32_t data_len;
	uint32_t tag_len;
	const uint8_t *key;
	const uint8_t *iv;
	const uint8_t *aad;
	const uint8_t *tag;
	const uint8_t *pt;
	const uint8_t *ct;
};

uint8_t data_buff[128];

#if 0
static struct gcm_data_s ae_test_data1 = {
	.key_len = sizeof(ae_data_aes_gcm_vect1_key),
	.iv_len = sizeof(ae_data_aes_gcm_vect1_nonce),
	.aad_len = sizeof(ae_data_aes_gcm_vect1_aad),
	.tag_len = sizeof(ae_data_aes_gcm_vect1_tag),
	.data_len = sizeof(ae_data_aes_gcm_vect1_ptx),
	.key = ae_data_aes_gcm_vect1_key,
	.iv = ae_data_aes_gcm_vect1_nonce,
	.tag = ae_data_aes_gcm_vect1_tag,
	.aad = ae_data_aes_gcm_vect1_aad,
	.pt = ae_data_aes_gcm_vect1_ptx,
	.ct = ae_data_aes_gcm_vect1_ctx,
};
#endif

static struct gcm_data_s ae_test_data2 = {
	.key_len = sizeof(ae_data_aes_gcm_vect2_key),
	.iv_len = sizeof(ae_data_aes_gcm_vect2_nonce),
	.aad_len = sizeof(ae_data_aes_gcm_vect2_aad),
	.tag_len = sizeof(ae_data_aes_gcm_vect2_tag),
	.data_len = sizeof(ae_data_aes_gcm_vect2_ptx),
	.key = ae_data_aes_gcm_vect2_key,
	.iv = ae_data_aes_gcm_vect2_nonce,
	.tag = ae_data_aes_gcm_vect2_tag,
	.aad = ae_data_aes_gcm_vect2_aad,
	.pt = ae_data_aes_gcm_vect2_ptx,
	.ct = ae_data_aes_gcm_vect2_ctx,
};

static struct gcm_data_s ae_test_data4 = {
	.key_len = sizeof(ae_data_aes_gcm_vect4_key),
	.iv_len = sizeof(ae_data_aes_gcm_vect4_nonce),
	.aad_len = sizeof(ae_data_aes_gcm_vect4_aad),
	.tag_len = sizeof(ae_data_aes_gcm_vect4_tag),
	.data_len = sizeof(ae_data_aes_gcm_vect4_ptx),
	.key = ae_data_aes_gcm_vect4_key,
	.iv = ae_data_aes_gcm_vect4_nonce,
	.tag = ae_data_aes_gcm_vect4_tag,
	.aad = ae_data_aes_gcm_vect4_aad,
	.pt = ae_data_aes_gcm_vect4_ptx,
	.ct = ae_data_aes_gcm_vect4_ctx,
};

static TEE_Result aes_gcm_test(uint32_t type, struct gcm_data_s *td);
TEE_Result ta_aes_gcm_test(void);
TEE_Result ta_aes_gcm_scp_test(void);

static TEE_Result aes_gcm_test(uint32_t type, struct gcm_data_s *td)
{
	TEE_Result res;
	TEE_ObjectHandle oh = TEE_HANDLE_NULL;
	TEE_OperationHandle op;
	TEE_Attribute key_attr;
	uint32_t attr_count;
	uint32_t key_size = 0;
	uint32_t obj_size = 0;
	uint32_t nonce_len = 0;
	uint32_t aad_len = 0;
	uint32_t payload_len = 0;
	uint32_t data_len = 0;
	uint32_t tag_len = 0;
	void *payload = NULL;
	void *nonce = NULL;
	void *aad = NULL;
	void *tag = NULL;

	GCM_DEBUG("AES-GCM test ...\n");
	key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
	key_attr.content.ref.buffer = (void *)td->key;
	key_attr.content.ref.length = td->key_len;
	key_size = td->key_len * 8;
	
	/* allocate operation */
	res = TEE_AllocateOperation(&op,
				    type,
				    TEE_MODE_DECRYPT,
				    key_size);
	if (res != TEE_SUCCESS) {
		GCM_ERROR("ae allocate operation error!\n");
		goto error2;
	}

	/* allocate transient object */
	obj_size = td->key_len * 8;
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, obj_size, &oh);
	if (res != TEE_SUCCESS) {
		GCM_ERROR("ae allocate transient object error!\n");
		goto error1;
	}

	/* populate transient object */
	attr_count = 1;
	res = TEE_PopulateTransientObject(oh, &key_attr, attr_count);
	if (res != TEE_SUCCESS) {
		GCM_ERROR("ae populate transient object error!\n");
		goto error1;
	}

	/* set operation */
	res = TEE_SetOperationKey(op, oh);
	if (res != TEE_SUCCESS) {
		GCM_ERROR("ae set operation error!\n");
		goto error1;
	}

	/* free transient object */
	TEE_FreeTransientObject(oh);
	oh = TEE_HANDLE_NULL;

	/* ae init */
	nonce = (void *)td->iv;
	nonce_len = td->iv_len;
	payload_len = td->data_len;
	tag_len = td->tag_len * 8; /* bits */
	res = TEE_AEInit(op, nonce, nonce_len,
			  tag_len, aad_len, payload_len);
	if (res != TEE_SUCCESS) {
		GCM_ERROR("ae init error! res: %x\n", res);
		goto error1;
	}

	/* ae update aad */
	aad = (void *)td->aad;
	aad_len = td->aad_len;
	TEE_AEUpdateAAD(op, aad, aad_len);

	/* ae update */
	payload = (void *)td->ct;
	payload_len = td->data_len;
	data_len = 128;

#if 0
	TEE_AEUpdate(op, payload, payload_len,
		     data_buff, &data_len);
#endif

	/* ae final */
	tag = (void *)td->tag;
	tag_len = td->tag_len;
	res = TEE_AEDecryptFinal(op, payload, payload_len,
				data_buff, &data_len,
				tag, tag_len);
	if (res != TEE_SUCCESS) {
		GCM_ERROR("ae decrypt final error! res: %x\n", res);
		goto error1;
	}

error1:
	/* free operation */
	TEE_FreeOperation(op);

error2:
	return res;
}

TEE_Result ta_aes_gcm_test(void)
{
	TEE_Result res;

	res = aes_gcm_test(TEE_ALG_AES_GCM, &ae_test_data2);

	res = aes_gcm_test(TEE_ALG_AES_GCM, &ae_test_data4);

	return res;
}

TEE_Result ta_aes_gcm_scp_test(void)
{
	TEE_Result res;

	res = aes_gcm_test(TEE_ALG_AES_GCM_SCP, &ae_test_data2);

	res = aes_gcm_test(TEE_ALG_AES_GCM_SCP, &ae_test_data4);

	return res;
}

