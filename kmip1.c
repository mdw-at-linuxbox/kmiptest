#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "kmip/kmip.h"
#include "kmip/kmip_bio.h"
#include "kmip/kmip_memset.h"

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
		else fprintf(out, "%- %s @ line: %d\n",
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

int process()
{
	int r = 666;
	struct my_kmip_connection kconn[1];
	size_t ns;
	int i;
	int need_to_free_response = 0;

	char *response = NULL;
	int response_size = 0;
	TextString *up;

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

	kmip_init(kconn->kmip_ctx, NULL, 0, KMIP_1_0);
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
	TextString nvalue[1];
	Name nattr[1];

	ap = a;
	ap->type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
	ap->value = &alg;
	++ap;
	ap->type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
	ap->value = &length;
	++ap;
	ap->type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
	ap->value = &mask;
	++ap;
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

	TemplateAttribute ta[1];
	memset(ta, 0, sizeof *ta);
	ta->attributes = a;
	ta->attribute_count = ap - a;

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
	memset(create_req, 0, sizeof *create_req);
	create_req->object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
	create_req->template_attribute = ta;

	RequestBatchItem rbi[1];
	memset(rbi, 0, sizeof *rbi);
	kmip_init_request_batch_item(rbi);
	rbi->operation = KMIP_OP_CREATE;
	rbi->request_payload = create_req;

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
		fprintf(stderr,"Stack trace: %s\n");
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
		fprintf(stderr,"Stack trace: %s\n");
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
		fprintf (stderr,"Failed to decode create response %d (", i);
		fprintf(stderr,"%s", my_decode_error_string(i));
		fprintf (stderr, ")\n");
		fprintf(stderr,"Context error: %s\n",
			kconn->kmip_ctx->error_message);
		fprintf(stderr,"Stack trace: %s\n");
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
	if (rs == KMIP_STATUS_SUCCESS) {
		CreateResponsePayload *pld = (CreateResponsePayload *)req->response_payload;
		if (pld) {
			if (Vflag) printf ("Symmetric key ID: ");
			if (pld->unique_identifier) {
				printf ("%.*s", (int)pld->unique_identifier->size,
					pld->unique_identifier->value);
			}
			printf ("\n");
		}
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

int main(int ac, char **av)
{
	char *ap, *ep, *cp;
	char *msg = 0;
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
	case 'V':
		++Vflag;
		break;
	default:
	Usage:
		if (msg) fprintf(stderr,"Error: %s\n", msg);
		fprintf(stderr,"Usage: kmip1 [-U user] [-P pw] [-C cacert] [-c cert] [-k key] [-n name] -p portno -h host\n");
		exit(1);
	} else {
		msg = "extra arg?";
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
	r = process();
	exit(r);
}
