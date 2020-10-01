#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iostream>
#include <iomanip>
#include <map>
#include <openssl/err.h>
#include <openssl/ssl.h>
extern "C" {
#include <kmip/kmip.h>
#include <kmip/kmip_bio.h>
#include <kmip/kmip_memset.h>
};

#if OPENSSL_VERSION_NUMBER < 0x10100003L
#define TLS_client_method SSLv23_client_method
#define OPENSSL_init_ssl(a,b)  SSL_library_init()
#endif

#include "kmip4lib.h"

int Vflag;
int iflag;
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


static int
kmip_write_an_error_helper(const char *s, size_t l, void *u) {
	std::ostream *out = static_cast<std::ostream *>(u);
	std::string es(s, l);
	*out << es << std::endl;
	return l;
}

void
ERR_put_errors(std::ostream &out)
{
	ERR_print_errors_cb(kmip_write_an_error_helper, &out);
}


int process(int op)
{
	int r = 666;
	my_kmip_connection kconn[1];
	size_t ns;
	int i;
	int need_to_free_response = 0;

	char *response = NULL;
	int response_size = 0;
	TextString *up;

	const char *what = "unknown";
	ResponseMessage resp_m[1];

	memset(resp_m, 0, sizeof *resp_m);

	{
	// generic initialization

	memset(kconn, 0, sizeof *kconn);
	OPENSSL_init_ssl(0, NULL);
	kconn->ctx = SSL_CTX_new(TLS_client_method());
	if (!clientcert)
		;
	else if (SSL_CTX_use_certificate_file(kconn->ctx, clientcert, SSL_FILETYPE_PEM) != 1) {
		std::cerr << "Can't load client cert from " << clientcert << std::endl;
		ERR_put_errors(std::cerr);
		r = 1;
		goto Done;
	}
	if (!clientkey)
		;
	else if (SSL_CTX_use_PrivateKey_file(kconn->ctx, clientkey, SSL_FILETYPE_PEM) != 1) {
		std::cerr << "Can't load client key from " << clientkey << std::endl;
		ERR_put_errors(std::cerr);
		r = 1;
		goto Done;
	}
	if (!cacert)
		;
	else if (SSL_CTX_load_verify_locations(kconn->ctx, cacert, NULL) != 1) {
		std::cerr << "Can't load cacert " << cacert << std::endl;
		ERR_put_errors(std::cerr);
		r = 1;
		goto Done;
	}
	if (!iflag)
		SSL_CTX_set_verify(kconn->ctx, SSL_VERIFY_PEER, NULL);
	kconn->bio = BIO_new_ssl_connect(kconn->ctx);
	if (!kconn->bio) {
		std::cerr << "BIO_new_ssl_connect failed" << std::endl;
		ERR_put_errors(std::cerr);
		r = 1;
		goto Done;
	}
	BIO_get_ssl(kconn->bio, &kconn->ssl);
	SSL_set_mode(kconn->ssl, SSL_MODE_AUTO_RETRY);

	// connect to kmip host

	BIO_set_conn_hostname(kconn->bio, host);
	BIO_set_conn_port(kconn->bio, portstring);
	if (BIO_do_connect(kconn->bio) != 1) {
		std::cerr << "BIO_do_connect failed to " << host << ' ' << portstring << std::endl;
		ERR_put_errors(std::cerr);
		r = 1;
		goto Done;
	}

	// setup kmip

	kmip_init(kconn->kmip_ctx, NULL, 0, protocol_version);
	kconn->need_to_free_kmip = 1;
	kconn->buffer_blocks = 1;
	kconn->buffer_block_size = 1024;
	kconn->encoding = static_cast<uint8*>(kconn->kmip_ctx->calloc_func(kconn->kmip_ctx->state, kconn->buffer_blocks, kconn->buffer_block_size));
	if (!kconn->encoding) {
		std::cerr << "kmip buffer alloc failed: "
			<< kconn->buffer_blocks << " * " << kconn->buffer_block_size << std::endl;
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
			std::cerr << "failed to add credential to kmip" << std::endl;
			r = 1;
			goto Done;
		}
	}

	// build the request message

	Attribute a[8], *ap;
	memset(a, 0, sizeof *a);
	for (i = 0; i < sizeof a/sizeof *a; ++i)
		kmip_init_attribute(a+i);
	cryptographic_algorithm alg = KMIP_CRYPTOALG_AES;
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
		std::cerr << "oops, missing operation request implementation" << std::endl;
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
std::cout << "Adding credential\n";
			auth->credential = static_cast<Credential *>(item->data);
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
		kconn->encoding = static_cast<uint8*>(kconn->kmip_ctx->calloc_func(kconn->kmip_ctx->state, kconn->buffer_blocks, kconn->buffer_block_size));
		if (!kconn->encoding) {
			std::cerr << "kmip buffer alloc failed: "
				<< kconn->buffer_blocks << '*' << kconn->buffer_block_size << std::endl;
			r = 1;
			goto Done;
		}
		ns = kconn->buffer_blocks * kconn->buffer_block_size;
		kmip_set_buffer(kconn->kmip_ctx, kconn->encoding, ns);
		kconn->buffer_total_size = ns;
	}
	if (i != KMIP_OK) {
		std::cerr << "Can't encode create request: " << i << " ("
			<< my_decode_error_string(i)
			<< ')' << std::endl;
		std::cerr << "Context error: " <<
			kconn->kmip_ctx->error_message << std::endl;
		std::cerr << "Stack trace:" << std::endl;
		std::cerr <<  kconn->kmip_ctx;
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
		std::cerr << "Problem sending request to create symmetric key: " << i << " ("
			<< my_decode_error_string(i)
			<< ')' << std::endl;
		std::cerr << "Context error: "
			<< kconn->kmip_ctx->error_message << std::endl;
		std::cerr << "Stack trace" << std::endl
			<<  kconn->kmip_ctx;
		r = 1;
		goto Done;
	}
	kmip_free_buffer(kconn->kmip_ctx,
		kconn->encoding,
		kconn->buffer_total_size);
	kconn->encoding = 0;
	kmip_set_buffer(kconn->kmip_ctx, response, response_size);
	need_to_free_response = 1;
	i = kmip_decode_response_message(kconn->kmip_ctx, resp_m);
	if (i != KMIP_OK) {
		std::cerr << "Failed to decode " << what << " response " << i << " ("
			<< my_decode_error_string(i) << ')' << std::endl;
		std::cerr << "Context error: "
			<< kconn->kmip_ctx->error_message << std::endl;
		std::cerr << "Stack trace" << std::endl
			<<  kconn->kmip_ctx;
		r = 1;
		goto Done;
	}
	if (Vflag)
		kmip_print_response_message(resp_m);
	ResponseBatchItem *req = resp_m->batch_items;
	enum result_status rs = req->result_status;
	std::cout << "result: " << rs
		<< " (" <<my_decode_result_status_enum(rs) << ')' << std::endl;
	if (rs != KMIP_STATUS_SUCCESS)
		;
	switch(op) {
	case OP_CREATE: {
		CreateResponsePayload *pld = static_cast<CreateResponsePayload *>(req->response_payload);
		if (pld) {
			if (Vflag) std::cout << "unique ID: ";
			if (pld->unique_identifier) {
				std::cout << std::string(
					pld->unique_identifier->value,
					pld->unique_identifier->size);
			}
			std::cout << std::endl;
		}
		} break;
	case OP_LOCATE: {
		LocateResponsePayload *pld = static_cast<LocateResponsePayload *>(req->response_payload);
		if (pld) {
			const char *sep = "";
			if (Vflag) std::cout << "located items " << pld->located_items << std::endl;
			if (Vflag) std::cout << "Unique Identifiers: "
				<< pld->unique_identifiers_count << std::endl;
			for (i = 0; i < pld->unique_identifiers_count; ++i) {
				std::cout << sep << std::string(pld->unique_identifiers[i].value,pld->unique_identifiers[i].size);
				sep = " ";
			}
			std::cout << std::endl;
		}
		} break;
	case OP_GET: {
		GetResponsePayload *pld = static_cast<GetResponsePayload *>(req->response_payload);
		if (pld) {
			if (Vflag) std::cout << "Object Type: ";
			std::cout << my_object_type_string(pld->object_type);
			if (Vflag) std::cout << "\nunique ID: ";
			else std::cout << '\t';
			if (pld->unique_identifier) {
				std::cout << std::string(
					pld->unique_identifier->value,
					pld->unique_identifier->size);
			}
			if (Vflag) std::cout << std::endl;
switch (pld->object_type) {
case KMIP_OBJTYPE_SYMMETRIC_KEY: {
		KeyBlock *kp = static_cast<SymmetricKey *>(pld->object)->key_block;
		ByteString *bp = 0;
		int count = 0;
		int i;
		ap = 0;
		if (Vflag) {
			std::cout << "key format: " <<
				my_key_format_type_string(kp->key_format_type)
				<< std::endl;
			std::cout << "key compression: " <<
				my_key_compression_type_string(kp->key_compression_type)
				<< std::endl;;
			std::cout << "key algorithm: " <<
				my_cryptographic_algorithm_string(kp->cryptographic_algorithm)
				<< std::endl;;
			std::cout << "cryptographic length: " <<
				kp->cryptographic_length << std::endl;
		} else std::cout << '\t';
		switch (kp->key_value_type) {
		case KMIP_TYPE_BYTE_STRING:
			bp = static_cast<ByteString*>(kp->key_value);
			break;
		case KMIP_TYPE_STRUCTURE: {
			KeyValue *kv = static_cast<KeyValue*>(kp->key_value);
			switch(kp->key_format_type) {
case KMIP_KEYFORMAT_RAW: case KMIP_KEYFORMAT_OPAQUE:
case KMIP_KEYFORMAT_PKCS1: case KMIP_KEYFORMAT_PKCS8:
case KMIP_KEYFORMAT_X509: case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
			bp = static_cast<ByteString*>(kv->key_material);
			break;
default:
std::cout << "?" "?-unknown-key-material";
			}
			ap = kv->attributes;
			count = kv->attribute_count;
			} break;
		default: std::cout << "??undecipherable key value";
		}
		if (bp) {
			for (i = 0; i < bp->size; ++i)
				std::cout << std::hex <<
					std::setfill ('0') << std::setw(2)
					<< static_cast<unsigned int>(i[bp->value]);
		}
		if (Vflag) std::cout << std::endl << "Attributes :" << std::endl;
		else std::cout << '\t';
		if (ap) for (i = 0; i < count; ++i) {
		} else std::cout << (Vflag ? "None" : "-");
		std::cout << std::endl;
	} break;
default:
	std::cout << "Unknown object at " << pld->object << std::endl;
}
		}
		} break;
	case OP_LISTATTRS: {
		GetAttributeListResponsePayload *pld = static_cast<GetAttributeListResponsePayload *>(req->response_payload);
		if (pld) {
			const char *sep = "";
			if (Vflag) std::cout << "Attribute names: "
				<< pld->attribute_names_count << std::endl;
			for (i = 0; i < pld->attribute_names_count; ++i) {
				std::cout << sep <<
					my_attribute_type_string(pld->attribute_names[i]);
				sep = ", ";
			}
			std::cout << std::endl;
		}
		} break;
	case OP_GETATTRS: {
		GetAttributesResponsePayload *pld = static_cast<GetAttributesResponsePayload *>(req->response_payload);
		if (pld) {
			const char *sep = "";
			if (Vflag) std::cout << "Attributes: " <<
				pld->attribute_count << std::endl;
			for (i = 0; i < pld->attribute_count; ++i) {
				char vtemp[512];
				my_attribute_value_string(vtemp, sizeof vtemp,
					pld->attributes[i].type,
					pld->attributes[i].value);
				std::cout << sep <<
					my_attribute_type_string(pld->attributes[i].type) <<
					'=' << vtemp;
				sep = ", ";
			}
			std::cout << std::endl;
		}
		} break;
	case OP_DESTROY: {
		DestroyResponsePayload *pld = static_cast<DestroyResponsePayload *>(req->response_payload);
		if (pld) {
			if (Vflag) std::cout << std::endl << "unique ID: ";
			if (pld->unique_identifier) {
				std::cout << std::string(
					pld->unique_identifier->value,
					pld->unique_identifier->size);
			}
			std::cout << std::endl;
		}
		} break;
	default:
		std::cerr << "oops, missing operation response implementation" << std::endl;
	}
	r = 0;
	}
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

std::map<std::string, kmip_version> protos {
	{"1.0",	KMIP_1_0},
	{"1.1",	KMIP_1_1},
	{"1.2",	KMIP_1_2},
	{"1.3",	KMIP_1_3},
	{"1.4",	KMIP_1_4},
	{"2.0",	KMIP_2_0}};

int set_protocol_version(char *ap)
{
	char *ep;
	int v;
	v = strtol(ap, &ep, 0);
	if (*ap && !*ep) {
		protocol_version = static_cast<kmip_version>(v);
		return 1;
	}
	auto protiter = protos.find(ap);
	if (protiter == protos.end()) {
		std::cerr << "Don't understand protocol <" << ap << '>' << std::endl;
		return 0;
	}
	protocol_version = protiter->second;
	return 1;
}

std::map<std::string, int> optable {
{ "create", OP_CREATE },
{ "locate", OP_LOCATE },
{ "get", OP_GET },
{ "lsattr", OP_LISTATTRS },
{ "getattr", OP_GETATTRS },
{ "destroy", OP_DESTROY }};

int main(int ac, char **av)
{
	char *ap, *ep, *cp;
	const char *msg = 0;
	char *op = 0;
	int r;

	while (--ac > 0) if (*(ap = *++av) == '-') while (*++ap) switch(*ap) {
//	case 'v':
//		++vflag;
//		break;
	case '-':
		break;
	case 'i':
		++iflag;
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
		if (msg) std::cerr << "Error: " << msg << std::endl;
		std::cerr << "Usage: kmip4 op [-U user] [-P pw] [-C cacert] [-c cert] [-k key] [-n name] -p portno -h host" << std::endl;
		std::cerr << "\top: create|locate|get|lsattr|getattr" << std::endl;
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
	auto opiter = optable.find(op);
	if (opiter == optable.end()) {
		msg = "Illegal operation?";
		goto Usage;
	}
	if (!host) {
		msg = "Missing host";
		goto Usage;
	}
	if (!portstring) {
		msg = "Missing portno";
		goto Usage;
	}
	r = process(opiter->second);
	exit(r);
}
