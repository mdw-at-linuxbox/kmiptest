#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <kmip/kmip.h>
#include <kmip/kmip_bio.h>
#include <kmip/kmip_memset.h>
#include "str.h"

#if OPENSSL_VERSION_NUMBER < 0x10100003L
#define TLS_client_method SSLv23_client_method
#define OPENSSL_init_ssl(a,b)  SSL_library_init()
#endif

int Vflag;
char *cacert;
char *host = 0;
char *clientcert = 0, *clientkey = 0;
char *portstring;
char *username;
char *password;
char *name;
char *unique_id;
enum kmip_version protocol_version = KMIP_1_0;

#define OP_CREATE 1
#define OP_LOCATE 2
#define OP_GET 3
#define OP_LISTATTRS 4
#define OP_GETATTRS 5
#define OP_DESTROY 6

char *my_object_type_string(enum object_type value)
{
	switch(value) {
	case 0:	return "-";
	case KMIP_OBJTYPE_CERTIFICATE: return "Certificate";
	case KMIP_OBJTYPE_SYMMETRIC_KEY: return "Symmetric Key";
	case KMIP_OBJTYPE_PUBLIC_KEY: return "Public Key";
	case KMIP_OBJTYPE_PRIVATE_KEY: return "Private Key";
	case KMIP_OBJTYPE_SPLIT_KEY: return "Split Key";
	case KMIP_OBJTYPE_TEMPLATE: return "Template";
	case KMIP_OBJTYPE_SECRET_DATA: return "Secret Data";
	case KMIP_OBJTYPE_OPAQUE_OBJECT: return "Opaque Object";
	case KMIP_OBJTYPE_PGP_KEY: return "PGP Key";
	case KMIP_OBJTYPE_CERTIFICATE_REQUEST: return "Certificate Request";
	default: return "Unknown";
	}
}

char *my_key_format_type_string(enum key_format_type i)
{
	switch(i) {
	case 0: return "-";
	case KMIP_KEYFORMAT_RAW: return "RAW";
	case KMIP_KEYFORMAT_OPAQUE: return "Opaque";
	case KMIP_KEYFORMAT_PKCS1: return "PKCS1";
	case KMIP_KEYFORMAT_PKCS8: return "PKCS8";
	case KMIP_KEYFORMAT_X509: return "X509";
	case KMIP_KEYFORMAT_EC_PRIVATE_KEY: return "EC Private Key";
	case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY: return "Transparent Symmetric Key";
	case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY: return "Transparent DSA Private Key";
	case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY: return "Transparent DSA Public Key";
	case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY: return "Transparent RSA Private Key";
	case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY: return "Transparent RSA Public Key";
	case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY: return "Transparent DH Private Key";
	case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY: return "Transparent DH Public Key";
	case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY: return "Transparent ECDSA Private Key";
	case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY: return "Transparent ECDSA Public Key";
	case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY: return "Transparent ECDH Private Key";
	case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY: return "Transparent ECDH Public Key";
	case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY: return "Transparent ECMQV Private Key";
	case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY: return "Transparent ECMQV Public Key";
	case KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY: return "Transparent EC Private Key";
	case KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY: return "Transparent EC Public Key";
	case KMIP_KEYFORMAT_PKCS12: return "PKCS#12";
	case KMIP_KEYFORMAT_PKCS10: return "PKCS#10";
	default: return "Unknown";
	}
}

char *my_key_compression_type_string(enum key_compression_type i)
{
	switch(i) {
	case 0: return "-";
	case KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED: return "EC Public Key Type Uncompressed";
	case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME: return "EC Public Key Type X9.62 Compressed Prime";
	case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2: return "EC Public Key Type X9.62 Compressed Char2";
	case KMIP_KEYCOMP_EC_PUB_X962_HYBRID: return "EC Public Key Type X9.62 Hybrid";
	default: return "Unknown";
	}
}

char *my_cryptographic_algorithm_string(enum cryptographic_algorithm i)
{
	switch(i) {
	case 0: return "-";
	case KMIP_CRYPTOALG_DES: return "DES";
	case KMIP_CRYPTOALG_TRIPLE_DES: return "3DES";
	case KMIP_CRYPTOALG_AES: return "AES";
	case KMIP_CRYPTOALG_RSA: return "RSA";
	case KMIP_CRYPTOALG_DSA: return "DSA";
	case KMIP_CRYPTOALG_ECDSA: return "ECDSA";
	case KMIP_CRYPTOALG_HMAC_SHA1: return "SHA1";
	case KMIP_CRYPTOALG_HMAC_SHA224: return "SHA224";
	case KMIP_CRYPTOALG_HMAC_SHA256: return "SHA256";
	case KMIP_CRYPTOALG_HMAC_SHA384: return "SHA384";
	case KMIP_CRYPTOALG_HMAC_SHA512: return "SHA512";
	case KMIP_CRYPTOALG_HMAC_MD5: return "MD5";
	case KMIP_CRYPTOALG_DH: return "DH";
	case KMIP_CRYPTOALG_ECDH: return "ECDH";
	case KMIP_CRYPTOALG_ECMQV: return "ECMQV";
	case KMIP_CRYPTOALG_BLOWFISH: return "BLOWFISH";
	case KMIP_CRYPTOALG_CAMELLIA: return "CAMELLIA";
	case KMIP_CRYPTOALG_CAST5: return "CAST5";
	case KMIP_CRYPTOALG_IDEA: return "IDEA";
	case KMIP_CRYPTOALG_MARS: return "MARS";
	case KMIP_CRYPTOALG_RC2: return "RC2";
	case KMIP_CRYPTOALG_RC4: return "RC4";
	case KMIP_CRYPTOALG_RC5: return "RC5";
	case KMIP_CRYPTOALG_SKIPJACK: return "SKIPJACK";
	case KMIP_CRYPTOALG_TWOFISH: return "TWOFISH";
	case KMIP_CRYPTOALG_EC: return "EC";
	case KMIP_CRYPTOALG_ONE_TIME_PAD: return "One Time Pad";
	case KMIP_CRYPTOALG_CHACHA20: return "ChaCha20";
	case KMIP_CRYPTOALG_POLY1305: return "Poly1305";
	case KMIP_CRYPTOALG_CHACHA20_POLY1305: return "ChaCha20 Poly1305";
	case KMIP_CRYPTOALG_SHA3_224: return "SHA3-224";
	case KMIP_CRYPTOALG_SHA3_256: return "SHA3-256";
	case KMIP_CRYPTOALG_SHA3_384: return "SHA3-384";
	case KMIP_CRYPTOALG_SHA3_512: return "SHA3-512";
	case KMIP_CRYPTOALG_HMAC_SHA3_224: return "HMAC SHA3-224";
	case KMIP_CRYPTOALG_HMAC_SHA3_256: return "HMAC SHA3-256";
	case KMIP_CRYPTOALG_HMAC_SHA3_384: return "HMAC SHA3-384";
	case KMIP_CRYPTOALG_HMAC_SHA3_512: return "HMAC SHA3-512";
	case KMIP_CRYPTOALG_SHAKE_128: return "SHAKE-128";
	case KMIP_CRYPTOALG_SHAKE_256: return "SHAKE-256";
	case KMIP_CRYPTOALG_ARIA: return "ARIA";
	case KMIP_CRYPTOALG_SEED: return "SEED";
	case KMIP_CRYPTOALG_SM2: return "SM2";
	case KMIP_CRYPTOALG_SM3: return "SM3";
	case KMIP_CRYPTOALG_SM4: return "SM4";
	case KMIP_CRYPTOALG_GOST_R_34_10_2012: return "GOST R 34.10-2012";
	case KMIP_CRYPTOALG_GOST_R_34_11_2012: return "GOST R 34.11-2012";
	case KMIP_CRYPTOALG_GOST_R_34_13_2015: return "GOST R 34.13-2015";
	case KMIP_CRYPTOALG_GOST_28147_89: return "GOST 28147-89";
	case KMIP_CRYPTOALG_XMSS: return "XMSS";
	case KMIP_CRYPTOALG_SPHINCS_256: return "SPHINCS-256";
	case KMIP_CRYPTOALG_MCELIECE: return "McEliece";
	case KMIP_CRYPTOALG_MCELIECE_6960119: return "McEliece 6960119";
	case KMIP_CRYPTOALG_MCELIECE_8192128: return "McEliece 8192128";
	case KMIP_CRYPTOALG_ED25519: return "Ed25519";
	case KMIP_CRYPTOALG_ED448: return "Ed448";
	default: return "Unknown";
	}
}

char *my_attribute_type_string(enum attribute_type value)
{
	switch(value) {
	case KMIP_ATTR_UNIQUE_IDENTIFIER:	return "Unique Identifier";
	case KMIP_ATTR_NAME:	return"Name";
	case KMIP_ATTR_OBJECT_TYPE:	return"Object Type";
	case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:	return"Cryptographic Algorithm";
	case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:	return"Cryptographic Length";
	case KMIP_ATTR_OPERATION_POLICY_NAME:	return"Operation Policy Name";
	case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:	return"Cryptographic Usage Mask";
	case KMIP_ATTR_STATE:	return"State";
	case KMIP_ATTR_DIGEST:	return "Digest";
	case KMIP_ATTR_LAST_CHANGE_DATE:	return "Last Change Date";
	case KMIP_ATTR_INITIAL_DATE:	return "Initial Date";
	case KMIP_ATTR_LEASE_TIME:	return "Lease Time";
	default:
		return "?";
	}
}
char *my_cryptographic_usage_mask_string(char *s, int n, int32 v)
{
	int kl;
	char *r = s;
	char *sep = "";
	for (sep = ""; (v) && kl>1; sep = ",") {
		if ((v&KMIP_CRYPTOMASK_SIGN)) {
			snprintf(s, n, "%ssign", sep);
			v &= ~KMIP_CRYPTOMASK_SIGN;
		} else if ((v&KMIP_CRYPTOMASK_VERIFY)) {
			snprintf(s, n, "%sverify", sep);
			v &= ~KMIP_CRYPTOMASK_VERIFY;
		} else if ((v&KMIP_CRYPTOMASK_ENCRYPT)) {
			snprintf(s, n, "%sencrypt", sep);
			v &= ~KMIP_CRYPTOMASK_ENCRYPT;
		} else if ((v&KMIP_CRYPTOMASK_DECRYPT)) {
			snprintf(s, n, "%sdecrypt", sep);
			v &= ~KMIP_CRYPTOMASK_DECRYPT;
		} else if ((v&KMIP_CRYPTOMASK_WRAP_KEY)) {
			snprintf(s, n, "%swrap_key", sep);
			v &= ~KMIP_CRYPTOMASK_WRAP_KEY;
		} else if ((v&KMIP_CRYPTOMASK_UNWRAP_KEY)) {
			snprintf(s, n, "%sunwrap_key", sep);
			v &= ~KMIP_CRYPTOMASK_UNWRAP_KEY;
		} else if ((v&KMIP_CRYPTOMASK_EXPORT)) {
			snprintf(s, n, "%sexport", sep);
			v &= ~KMIP_CRYPTOMASK_EXPORT;
		} else if ((v&KMIP_CRYPTOMASK_MAC_GENERATE)) {
			snprintf(s, n, "%smac_generate", sep);
			v &= ~KMIP_CRYPTOMASK_MAC_GENERATE;
		} else if ((v&KMIP_CRYPTOMASK_MAC_VERIFY)) {
			snprintf(s, n, "%smac_verify", sep);
			v &= ~KMIP_CRYPTOMASK_MAC_VERIFY;
		} else if ((v&KMIP_CRYPTOMASK_DERIVE_KEY)) {
			snprintf(s, n, "%sderive_key", sep);
			v &= ~KMIP_CRYPTOMASK_DERIVE_KEY;
		} else if ((v&KMIP_CRYPTOMASK_CONTENT_COMMITMENT)) {
			snprintf(s, n, "%scontent_commitment", sep);
			v &= ~KMIP_CRYPTOMASK_CONTENT_COMMITMENT;
		} else if ((v&KMIP_CRYPTOMASK_KEY_AGREEMENT)) {
			snprintf(s, n, "%skey_agreement", sep);
			v &= ~KMIP_CRYPTOMASK_KEY_AGREEMENT;
		} else if ((v&KMIP_CRYPTOMASK_CERTIFICATE_SIGN)) {
			snprintf(s, n, "%scertificate_sign", sep);
			v &= ~KMIP_CRYPTOMASK_CERTIFICATE_SIGN;
		} else if ((v&KMIP_CRYPTOMASK_CRL_SIGN)) {
			snprintf(s, n, "%scrl_sign", sep);
			v &= ~KMIP_CRYPTOMASK_CRL_SIGN;
		} else if ((v&KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM)) {
			snprintf(s, n, "%sgenerate_cryptogram", sep);
			v &= ~KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM;
		} else if ((v&KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM)) {
			snprintf(s, n, "%svalidate_cryptogram", sep);
			v &= ~KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM;
		} else if ((v&KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT)) {
			snprintf(s, n, "%stranslate_encrypt", sep);
			v &= ~KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT;
		} else if ((v&KMIP_CRYPTOMASK_TRANSLATE_DECRYPT)) {
			snprintf(s, n, "%stranslate_decrypt", sep);
			v &= ~KMIP_CRYPTOMASK_TRANSLATE_DECRYPT;
		} else if ((v&KMIP_CRYPTOMASK_TRANSLATE_WRAP)) {
			snprintf(s, n, "%stranslate_wrap", sep);
			v &= ~KMIP_CRYPTOMASK_TRANSLATE_WRAP;
		} else if ((v&KMIP_CRYPTOMASK_TRANSLATE_UNWRAP)) {
			snprintf(s, n, "%stranslate_unwrap", sep);
			v &= ~KMIP_CRYPTOMASK_TRANSLATE_UNWRAP;
		} else if ((v&KMIP_CRYPTOMASK_AUTHENTICATE)) {
			snprintf(s, n, "%sauthenticate", sep);
			v &= ~KMIP_CRYPTOMASK_AUTHENTICATE;
		} else if ((v&KMIP_CRYPTOMASK_UNRESTRICTED)) {
			snprintf(s, n, "%sunrestricted", sep);
			v &= ~KMIP_CRYPTOMASK_UNRESTRICTED;
		} else if ((v&KMIP_CRYPTOMASK_FPE_ENCRYPT)) {
			snprintf(s, n, "%sfpe_encrypt", sep);
			v &= ~KMIP_CRYPTOMASK_FPE_ENCRYPT;
		} else if ((v&KMIP_CRYPTOMASK_FPE_DECRYPT)) {
			snprintf(s, n, "%sfpe_decrypt", sep);
			v &= ~KMIP_CRYPTOMASK_FPE_DECRYPT;
		} else {
			snprintf(s, n, "%s%#x", (*sep ? "+" : ""), v);
			v = 0;
		}
		kl = strlen(s);
		s += kl;
		n -= kl;
	}
	return r;
}

char *my_attribute_value_string(char *s, int n, enum attribute_type type, void *value)
{
	char *t;
	switch(type) {
	case KMIP_ATTR_UNIQUE_IDENTIFIER:
		snprintf(s, n, "%.*s",
			(int)((TextString*)value)->size,
			((TextString*)value)->value);
		break;
	case KMIP_ATTR_NAME:
		switch(((Name*)value)->type) {
		case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
			t = "s";
			break;
		case KMIP_NAME_URI:
			t = "uri";
			break;
		default:
			t = "?";
		}
		snprintf(s, n, "(%s)%.*s",
			t,
			(int)((Name*)value)->value->size,
			((Name*)value)->value->value);
		break;
	case KMIP_ATTR_OBJECT_TYPE:
		snprintf(s, n, my_object_type_string(*(enum object_type*)value));
		break;
	case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
		snprintf(s, n, my_cryptographic_algorithm_string(*(enum cryptographic_algorithm*)value));
		break;
	case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
		snprintf(s, n, "%d", *(int32 *)value);
		break;
	case KMIP_ATTR_OPERATION_POLICY_NAME:
		snprintf(s, n, "%.*s",
			(int)((TextString*)value)->size,
			((TextString*)value)->value);
		break;
	case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
		s = my_cryptographic_usage_mask_string(s, n, *(int32*)value);
		break;
	case KMIP_ATTR_STATE:
	default:
		snprintf(s, n, "?");
		break;
	}
	return s;
}

char *my_decode_error_string(int i)
{
	switch(i) {
        case 0:		return "KMIP_OK";
        case -1:	return "KMIP_NOT_IMPLEMENTED";
        case -2:	return "KMIP_ERROR_BUFFER_FULL";
        case -3:	return "KMIP_ERROR_ATTR_UNSUPPORTED";
        case -4:	return "KMIP_TAG_MISMATCH";
        case -5:	return "KMIP_TYPE_MISMATCH";
        case -6:	return "KMIP_LENGTH_MISMATCH";
        case -7:	return "KMIP_PADDING_MISMATCH";
        case -8:	return "KMIP_BOOLEAN_MISMATCH";
        case -9:	return "KMIP_ENUM_MISMATCH";
        case -10:	return "KMIP_ENUM_UNSUPPORTED";
        case -11:	return "KMIP_INVALID_FOR_VERSION";
        case -12:	return "KMIP_MEMORY_ALLOC_FAILED";
        case -13:	return "KMIP_IO_FAILURE";
        case -14:	return "KMIP_EXCEED_MAX_MESSAGE_SIZE";
        case -15:	return "KMIP_MALFORMED_RESPONSE";
        case -16:	return "KMIP_OBJECT_MISMATCH";
        case -17:	return "KMIP_ARG_INVALID";
        case -18:	return "KMIP_ERROR_BUFFER_UNDERFULL";
	default:	return "?";
	}
}

char *my_decode_result_status_enum(enum result_status i)
{
	switch(i) {
	case KMIP_STATUS_SUCCESS:	return "Success";
	case KMIP_STATUS_OPERATION_FAILED:	return "Operation Failed";
	case KMIP_STATUS_OPERATION_PENDING:	return "Operation Pending";
	case KMIP_STATUS_OPERATION_UNDONE:	return "Operation Undone";
	default:	return "?";
	}
}

void
my_fprint_stacked_errors(FILE *out, KMIP *ctx)
{
	ErrorFrame *ef;

	if (!ctx) return;
	for (ef = ctx->frame_index; ef >= ctx->errors; --ef)
		if (!ef->line)
			;
		else fprintf(out, "- %s @ line: %d\n",
			ef->function, ef->line);
}

struct my_kmip_connection {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	KMIP kmip_ctx[1];
	TextString textstrings[2];
	UsernamePasswordCredential upc[1];
	Credential credential[1];
	int need_to_free_kmip;
	size_t buffer_blocks, buffer_block_size, buffer_total_size;
	uint8 *encoding;
};

int process(int op)
{
	int r = 666;
	struct my_kmip_connection kconn[1];
	size_t ns;
	int i;
	int need_to_free_response = 0;

	char *response = NULL;
	int response_size = 0;
	TextString *up;

	char *what = "unknown";

	// generic initialization

	memset(kconn, 0, sizeof *kconn);
	OPENSSL_init_ssl(0, NULL);
	kconn->ctx = SSL_CTX_new(TLS_client_method());
	if (!clientcert)
		;
	else if (SSL_CTX_use_certificate_file(kconn->ctx, clientcert, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr,"Can't load client cert from %s\n", clientcert);
		ERR_print_errors_fp(stderr);
		r = 1;
		goto Done;
	}
	if (!clientkey)
		;
	else if (SSL_CTX_use_PrivateKey_file(kconn->ctx, clientkey, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr,"Can't load client key from %s\n", clientkey);
		ERR_print_errors_fp(stderr);
		r = 1;
		goto Done;
	}
	if (!cacert)
		;
	else if (SSL_CTX_load_verify_locations(kconn->ctx, cacert, NULL) != 1) {
		fprintf(stderr,"Can't load cacert %s\n", cacert);
		ERR_print_errors_fp(stderr);
		r = 1;
		goto Done;
	}
	kconn->bio = BIO_new_ssl_connect(kconn->ctx);
	if (!kconn->bio) {
		fprintf(stderr,"BIO_new_ssl_connect failed\n");
		ERR_print_errors_fp(stderr);
		r = 1;
		goto Done;
	}
	BIO_get_ssl(kconn->bio, &kconn->ssl);
	SSL_set_mode(kconn->ssl, SSL_MODE_AUTO_RETRY);

	// connect to kmip host

	BIO_set_conn_hostname(kconn->bio, host);
	BIO_set_conn_port(kconn->bio, portstring);
	if (BIO_do_connect(kconn->bio) != 1) {
		fprintf(stderr,"BIO_do_connect failed to %s %s\n", host, portstring);
		ERR_print_errors_fp(stderr);
		r = 1;
		goto Done;
	}

	// setup kmip

	kmip_init(kconn->kmip_ctx, NULL, 0, protocol_version);
	kconn->need_to_free_kmip = 1;
	kconn->buffer_blocks = 1;
	kconn->buffer_block_size = 1024;
	kconn->encoding = kconn->kmip_ctx->calloc_func(kconn->kmip_ctx->state, kconn->buffer_blocks, kconn->buffer_block_size);
	if (!kconn->encoding) {
		fprintf (stderr,"kmip buffer alloc failed: %d * %d\n",
			kconn->buffer_blocks, kconn->buffer_block_size);
		r = 1;
		goto Done;
	}
	ns = kconn->buffer_blocks * kconn->buffer_block_size;
	kmip_set_buffer(kconn->kmip_ctx, kconn->encoding, ns);
	kconn->buffer_total_size = ns;

	// add credential

	up = kconn->textstrings;
	if (username) {
		memset(kconn->upc, 0, sizeof *kconn->upc);
		up->value = username;
		up->size = strlen(username);
		kconn->upc->username = up++;
		if (password) {
			up->value = password;
			up->size = strlen(password);
			kconn->upc->password = up++;
		}
		kconn->credential->credential_type = KMIP_CRED_USERNAME_AND_PASSWORD;
		kconn->credential->credential_value = kconn->upc;
		i = kmip_add_credential(kconn->kmip_ctx, kconn->credential);
		if (i != KMIP_OK) {
			fprintf(stderr,"failed to add credential to kmip\n");
			r = 1;
			goto Done;
		}
	}

	// build the request message

	Attribute a[8], *ap;
	memset(a, 0, sizeof *a);
	for (i = 0; i < sizeof a/sizeof *a; ++i)
		kmip_init_attribute(a+i);
	enum cryptographic_algorithm alg = KMIP_CRYPTOALG_AES;
	int32 length = 256;
	int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
	TextString nvalue[1], uvalue[1];
	Name nattr[1];
	ap = a;

	switch(op) {
	case OP_CREATE:
		ap->type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
		ap->value = &alg;
		++ap;
		ap->type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
		ap->value = &length;
		++ap;
		ap->type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
		ap->value = &mask;
		++ap;
		break;
	}
	if (name) {
		memset(nvalue, 0, sizeof *nvalue);
		nvalue->value = name;
		nvalue->size = strlen(name);
		memset(nattr, 0, sizeof *nattr);
		nattr->value = nvalue;
		nattr->type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
		ap->type = KMIP_ATTR_NAME;
		ap->value = nattr;
		++ap;
	}
	if (unique_id) {
		memset(uvalue, 0, sizeof *uvalue);
		uvalue->value = unique_id;
		uvalue->size = strlen(unique_id);
	}

	ProtocolVersion pv[1];
	memset(pv, 0, sizeof *pv);
	kmip_init_protocol_version(pv, kconn->kmip_ctx->version);

	RequestHeader rh[1];
	memset(rh, 0, sizeof *rh);
	kmip_init_request_header(rh);
	rh->protocol_version = pv;
	rh->maximum_response_size = kconn->kmip_ctx->max_message_size;
	rh->time_stamp = time(NULL);
	rh->batch_count = 1;

	CreateRequestPayload create_req[1];
	LocateRequestPayload locate_req[1];
	GetRequestPayload get_req[1];
	GetAttributeListRequestPayload lsattrs_req[1];
	GetAttributesRequestPayload getattrs_req[1];
	DestroyRequestPayload destroy_req[1];
	RequestBatchItem rbi[1];
	TemplateAttribute ta[1];
	memset(rbi, 0, sizeof *rbi);
	kmip_init_request_batch_item(rbi);
	switch (op) {
	case OP_CREATE:
		memset(ta, 0, sizeof *ta);
		ta->attributes = a;
		ta->attribute_count = ap - a;

		memset(create_req, 0, sizeof *create_req);
		create_req->object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
		create_req->template_attribute = ta;

		rbi->operation = KMIP_OP_CREATE;
		rbi->request_payload = create_req;
		what = "create";
		break;
	case OP_GET:
		memset(get_req, 0, sizeof *get_req);
		if (unique_id)
			get_req->unique_identifier = uvalue;;
//		get_req->key_compression_type =
//		get_req->key_wrapping_spec =

		rbi->operation = KMIP_OP_GET;
		rbi->request_payload = get_req;
		what = "get";
		break;
	case OP_LOCATE:
		memset(locate_req, 0, sizeof *locate_req);
		if (ap > a) {
			locate_req->attributes = a;
			locate_req->attribute_count = ap - a;
		}
		rbi->operation = KMIP_OP_LOCATE;
		rbi->request_payload = locate_req;
		what = "locate";
		break;
	case OP_LISTATTRS:
		memset(lsattrs_req, 0, sizeof *lsattrs_req);
		if (unique_id)
			lsattrs_req->unique_identifier = uvalue;;
		rbi->operation = KMIP_OP_GET_ATTRIBUTE_LIST;
		rbi->request_payload = lsattrs_req;
		what = "get attribute list";
		break;
	case OP_GETATTRS:
		memset(getattrs_req, 0, sizeof *getattrs_req);
		if (unique_id)
			getattrs_req->unique_identifier = uvalue;;
		rbi->operation = KMIP_OP_GET_ATTRIBUTES;
		rbi->request_payload = getattrs_req;
		what = "get attributes";
		break;
	case OP_DESTROY:
		memset(destroy_req, 0, sizeof *destroy_req);
		if (unique_id)
			destroy_req->unique_identifier = uvalue;;
		rbi->operation = KMIP_OP_DESTROY;
		rbi->request_payload = destroy_req;
		what = "destroy";
		break;
	default:
		fprintf(stderr,"oops, missing operation request implementation\n");
		r = 1;
		goto Done;
	}

	RequestMessage rm[1];
	memset(rm, 0, sizeof *rm);
	rm->request_header = rh;
	rm->batch_items = rbi;
	rm->batch_count = 1;

	Authentication auth[1];
	memset(auth, 0, sizeof *auth);
	if (kconn->kmip_ctx->credential_list) {
		LinkedListItem *item = kconn->kmip_ctx->credential_list->head;
		if (item) {
printf ("Adding credential\n");
			auth->credential = (Credential *)item->data;
			rh->authentication = auth;
		}
	}

	for (;;) {
		i = kmip_encode_request_message(kconn->kmip_ctx, rm);
		if (i != KMIP_ERROR_BUFFER_FULL) break;
		kmip_reset(kconn->kmip_ctx);
		kconn->kmip_ctx->free_func(kconn->kmip_ctx->state, kconn->encoding);
		kconn->encoding = 0;
		++kconn->buffer_blocks;
		kconn->encoding = kconn->kmip_ctx->calloc_func(kconn->kmip_ctx->state, kconn->buffer_blocks, kconn->buffer_block_size);
		if (!kconn->encoding) {
			fprintf (stderr,"kmip buffer alloc failed: %d * %d\n",
				kconn->buffer_blocks, kconn->buffer_block_size);
			r = 1;
			goto Done;
		}
		ns = kconn->buffer_blocks * kconn->buffer_block_size;
		kmip_set_buffer(kconn->kmip_ctx, kconn->encoding, ns);
		kconn->buffer_total_size = ns;
	}
	if (i != KMIP_OK) {
		fprintf(stderr,"Can't encode create request: %d (", i);
		fprintf(stderr,"%s", my_decode_error_string(i));
		fprintf(stderr,")\n");
		fprintf(stderr,"Context error: %s\n",
			kconn->kmip_ctx->error_message);
		fprintf(stderr,"Stack trace:\n");
		my_fprint_stacked_errors(stderr, kconn->kmip_ctx);
		r = 1;
		goto Done;
	}

	if (Vflag) {
		kmip_print_request_message(rm);
		putchar('\n');
	}

	i = kmip_bio_send_request_encoding(kconn->kmip_ctx, kconn->bio,
		(char*)kconn->encoding,
		kconn->kmip_ctx->index - kconn->kmip_ctx->buffer,
		&response, &response_size);
	if (i < 0) {
		fprintf(stderr,"Problem sending request to create symmetric key: %d (", i);
		fprintf(stderr,"%s", my_decode_error_string(i));
		fprintf(stderr,")\n");
		fprintf(stderr,"Context error: %s\n",
			kconn->kmip_ctx->error_message);
		fprintf(stderr,"Stack trace\n");
		my_fprint_stacked_errors(stderr, kconn->kmip_ctx);
		r = 1;
		goto Done;
	}
	kmip_free_buffer(kconn->kmip_ctx,
		kconn->encoding,
		kconn->buffer_total_size);
	kconn->encoding = 0;
	kmip_set_buffer(kconn->kmip_ctx, response, response_size);
	ResponseMessage resp_m[1];
	memset(resp_m, 0, sizeof *resp_m);
	need_to_free_response = 1;
	i = kmip_decode_response_message(kconn->kmip_ctx, resp_m);
	if (i != KMIP_OK) {
		fprintf (stderr,"Failed to decode %s response %d (", what, i);
		fprintf(stderr,"%s", my_decode_error_string(i));
		fprintf (stderr, ")\n");
		fprintf(stderr,"Context error: %s\n",
			kconn->kmip_ctx->error_message);
		fprintf(stderr,"Stack trace\n");
		my_fprint_stacked_errors(stderr, kconn->kmip_ctx);
		r = 1;
		goto Done;
	}
	if (Vflag)
		kmip_print_response_message(resp_m);
	ResponseBatchItem *req = resp_m->batch_items;
	enum result_status rs = req->result_status;
	printf ("result: %d (", rs);
	fprintf(stdout,"%s", my_decode_result_status_enum(rs));
	printf (")\n");
	if (rs != KMIP_STATUS_SUCCESS)
		;
	switch(op) {
	case OP_CREATE: {
		CreateResponsePayload *pld = (CreateResponsePayload *)req->response_payload;
		if (pld) {
			if (Vflag) printf ("unique ID: ");
			if (pld->unique_identifier) {
				printf ("%.*s", (int)pld->unique_identifier->size,
					pld->unique_identifier->value);
			}
			printf ("\n");
		}
		} break;
	case OP_LOCATE: {
		LocateResponsePayload *pld = (LocateResponsePayload *)req->response_payload;
		if (pld) {
			char *sep = "";
			if (Vflag) printf ("located items %d\n", pld->located_items);
			if (Vflag) printf ("Unique Identifiers: %d\n",
				pld->unique_identifiers_count);
			for (i = 0; i < pld->unique_identifiers_count; ++i) {
				printf ("%s%s", sep, pld->unique_identifiers[i]);
				sep = " ";
			}
			printf ("\n");
		}
		} break;
	case OP_GET: {
		GetResponsePayload *pld = (GetResponsePayload *)req->response_payload;
		if (pld) {
			if (Vflag) printf ("Object Type: ");
			printf ("%s", my_object_type_string(pld->object_type));
			if (Vflag) printf ("\nunique ID: ");
			else printf ("\t");
			if (pld->unique_identifier) {
				printf ("%.*s", (int)pld->unique_identifier->size,
					pld->unique_identifier->value);
			}
			if (Vflag) printf ("\n");
switch (pld->object_type) {
case KMIP_OBJTYPE_SYMMETRIC_KEY: {
		KeyBlock *kp = ((SymmetricKey *)pld->object)->key_block;
		ByteString *bp = 0;
		int count = 0;
		int i;
		ap = 0;
		if (Vflag) {
			printf ("key format: %s\n",
				my_key_format_type_string(kp->key_format_type));
			printf ("key compression: %s\n",
				my_key_compression_type_string(kp->key_compression_type));
			printf ("key algorithm: %s\n",
				my_cryptographic_algorithm_string(kp->cryptographic_algorithm));
			printf ("cryptographic length: %d\n",
				kp->cryptographic_length);
		} else printf ("\t");
		switch (kp->key_value_type) {
		case KMIP_TYPE_BYTE_STRING:
			bp = kp->key_value;
			break;
		case KMIP_TYPE_STRUCTURE: {
			KeyValue *kv = kp->key_value;
			switch(kp->key_format_type) {
case KMIP_KEYFORMAT_RAW: case KMIP_KEYFORMAT_OPAQUE:
case KMIP_KEYFORMAT_PKCS1: case KMIP_KEYFORMAT_PKCS8:
case KMIP_KEYFORMAT_X509: case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
			bp = kv->key_material;
			break;
default:
printf ("?" "?-unknown-key-material");
			}
			ap = kv->attributes;
			count = kv->attribute_count;
			} break;
		default: printf ("??undecipherable key value");
		}
		if (bp) {
			for (i = 0; i < bp->size; ++i)
				printf ("%02x", i[bp->value]);
		}
		if (Vflag) printf ("\nAttributes :\n");
		else printf ("\t");
		if (ap) for (i = 0; i < count; ++i) {
		} else printf (Vflag ? "None" : "-");
		printf ("\n");
	} break;
default:
	printf("Unknown object at %p\n", (long int) (pld->object));
}
		}
		} break;
	case OP_LISTATTRS: {
		GetAttributeListResponsePayload *pld = (GetAttributeListResponsePayload *)req->response_payload;
		if (pld) {
			char *sep = "";
			if (Vflag) printf ("Attribute names: %d\n",
				pld->attribute_names_count);
			for (i = 0; i < pld->attribute_names_count; ++i) {
				printf ("%s%s", sep,
					my_attribute_type_string(pld->attribute_names[i]));
				sep = ", ";
			}
			printf ("\n");
		}
		} break;
	case OP_GETATTRS: {
		GetAttributesResponsePayload *pld = (GetAttributesResponsePayload *)req->response_payload;
		if (pld) {
			char *sep = "";
			if (Vflag) printf ("Attributes: %d\n",
				pld->attribute_count);
			for (i = 0; i < pld->attribute_count; ++i) {
				char vtemp[512];
				my_attribute_value_string(vtemp, sizeof vtemp,
					pld->attributes[i].type,
					pld->attributes[i].value);
				printf ("%s%s=%s",
					sep,
					my_attribute_type_string(pld->attributes[i].type),
					vtemp);
				sep = ", ";
			}
			printf ("\n");
		}
		} break;
	case OP_DESTROY: {
		DestroyResponsePayload *pld = (DestroyResponsePayload *)req->response_payload;
		if (pld) {
			if (Vflag) printf ("\nunique ID: ");
			if (pld->unique_identifier) {
				printf ("%.*s", (int)pld->unique_identifier->size,
					pld->unique_identifier->value);
			}
			printf ("\n");
		}
		} break;
	default:
		fprintf(stderr,"oops, missing operation response implementation\n");
	}
	r = 0;
Done:
	if (need_to_free_response)
		kmip_free_response_message(kconn->kmip_ctx, resp_m);
	int set_null_buffer = 0;
	if (response) {
		kmip_free_buffer(kconn->kmip_ctx, response, response_size);
		set_null_buffer = 1;
	}
	if (kconn->encoding) {
		kmip_free_buffer(kconn->kmip_ctx,
			kconn->encoding,
			kconn->buffer_total_size);
		set_null_buffer = 1;
	}
	if (set_null_buffer)
		kmip_set_buffer(kconn->kmip_ctx, NULL, 0);
	if (kconn->need_to_free_kmip) kmip_destroy(kconn->kmip_ctx);
	if (kconn->bio) BIO_free_all(kconn->bio);
	if (kconn->ctx) SSL_CTX_free(kconn->ctx);
	return r;
}

char *protos[] = {
	"1.0",	// 1 = KMIP_1_0 (0)
	"1.1",	// 2 = KMIP_1_1 (1)
	"1.2",	// 3 = KMIP_1_2 (2)
	"1.3",	// 4 = KMIP_1_3 (3)
	"1.4",	// 5 = KMIP_1_4 (4)
	"2.0",	// 6 = KMIP_2_0 (5)
0};

int set_protocol_version(char *ap)
{
	char *ep;
	int v;
	v = strtol(ap, &ep, 0);
	if (*ap && !*ep) {
		protocol_version = v;
		return 1;
	}
	switch(kwscan(ap, protos)) {
	default:
	fprintf(stderr,"Don't understand protocol <%s>\n", ap);
		return 0;
	case 1:	protocol_version = KMIP_1_0; break;
	case 2:	protocol_version = KMIP_1_1; break;
	case 3:	protocol_version = KMIP_1_2; break;
	case 4:	protocol_version = KMIP_1_3; break;
	case 5:	protocol_version = KMIP_1_4; break;
	case 6:	protocol_version = KMIP_2_0; break;
	}
	return 1;
}

char *optable[] = {
	"create",
	"locate",
	"get",
	"lsattr",
	"getattr",
	"destroy",
0};

int main(int ac, char **av)
{
	char *ap, *ep, *cp;
	char *msg = 0;
	char *op = 0;
	int r;

	while (--ac > 0) if (*(ap = *++av) == '-') while (*++ap) switch(*ap) {
//	case 'v':
//		++vflag;
//		break;
	case '-':
		break;
	case 'h':
		if (ac < 1) {
			msg = "-h: missing host";
			goto Usage;
		}
		--ac;
		host = *++av;
		break;
	case 'p':
		if (ac < 1) {
			msg = "-p: missing portno";
			goto Usage;
		}
		--ac;
		portstring = *++av;
		break;
	case 'u':
		if (ac < 1) {
			msg = "-k: missing unique-identifer";
			goto Usage;
		}
		--ac;
		unique_id = *++av;
		break;
	case 'k':
		if (ac < 1) {
			msg = "-k: missing clientkey";
			goto Usage;
		}
		--ac;
		clientkey = *++av;
		break;
	case 'c':
		if (ac < 1) {
			msg = "-c: missing clientcert";
			goto Usage;
		}
		--ac;
		clientcert = *++av;
		break;
	case 'C':
		if (ac < 1) {
			msg = "-C: missing cafile";
			goto Usage;
		}
		--ac;
		cacert = *++av;
		break;
	case 'U':
		if (ac < 1) {
			msg = "-U: missing username";
			goto Usage;
		}
		--ac;
		username = *++av;
		break;
	case 'P':
		if (ac < 1) {
			msg = "-P: missing password";
			goto Usage;
		}
		--ac;
		password = *++av;
		break;
	case 'n':
		if (ac < 1) {
			msg = "-P: missing name";
			goto Usage;
		}
		--ac;
		name = *++av;
		break;
	case 'Q':
		if (ac < 1) {
			msg = "-P: missing name";
			goto Usage;
		}
		--ac;
		if (!set_protocol_version(*++av))
			goto Usage;
		break;
	case 'V':
		++Vflag;
		break;
	default:
	Usage:
		if (msg) fprintf(stderr,"Error: %s\n", msg);
		fprintf(stderr,"Usage: kmip2 op [-U user] [-P pw] [-C cacert] [-c cert] [-k key] [-n name] -p portno -h host\n\top: create|locate|get|lsattr|getattr\n");
		exit(1);
	} else {
		if (op) {
			msg = "extra arg?";
			goto Usage;
		}
		op = ap;
	}
	if (!op) {
		msg = "Missing operation?";
		goto Usage;
	}
	switch(r = kwscan(op, optable)) {
	case 0:
		msg = "Illegal operation?";
		goto Usage;
//	case 1:	// OP_CREATE
//	case 2:	// OP_LOCATE
//	case 3:	// OP_GET
//	case 4:	// OP_LISTATTRS
//	case 5:	// OP_GETATTRS
//	case 6:	// OP_DESTROY
	}
	if (!host) {
		msg = "Missing host";
		goto Usage;
	}
	if (!portstring) {
		msg = "Missing portno";
		goto Usage;
	}
	r = process(r);
	exit(r);
}
