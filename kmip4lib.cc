#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
extern "C" {
#include <kmip/kmip.h>
#include <kmip/kmip_bio.h>
#include <kmip/kmip_memset.h>
};

#include "kmip4lib.h"

const char *my_object_type_string(enum object_type value)
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

const char *my_key_format_type_string(enum key_format_type i)
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

const char *my_key_compression_type_string(enum key_compression_type i)
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

const char *my_cryptographic_algorithm_string(enum cryptographic_algorithm i)
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

const char *my_attribute_type_string(enum attribute_type value)
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

const char *my_cryptographic_usage_mask_string(char *s, int n, int32 v)
{
	int kl;
	char *r = s;
	const char *sep = "";
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

const char *my_attribute_value_string(char *s, int n, enum attribute_type type, void *value)
{
	const char *t;
	const char *rs = s;
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
		rs = my_cryptographic_usage_mask_string(s, n, *(int32*)value);
		break;
	case KMIP_ATTR_STATE:
	default:
		snprintf(s, n, "?");
		break;
	}
	return rs;
}

const char *my_decode_error_string(int i)
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

const char *my_decode_result_status_enum(enum result_status i)
{
	switch(i) {
	case KMIP_STATUS_SUCCESS:	return "Success";
	case KMIP_STATUS_OPERATION_FAILED:	return "Operation Failed";
	case KMIP_STATUS_OPERATION_PENDING:	return "Operation Pending";
	case KMIP_STATUS_OPERATION_UNDONE:	return "Operation Undone";
	default:	return "?";
	}
}

std::ostream& operator<<(std::ostream &out, KMIP *ctx)
{
	ErrorFrame *ef;

	if (!ctx)
		;
	else for (ef = ctx->frame_index; ef >= ctx->errors; --ef)
		if (!ef->line)
			;
		else
			out << "- " << ef->function << " @ line: "
				<< ef->line << std::endl;
	return out;
}
