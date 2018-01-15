#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#ifndef __AWS_TLS__H__
#define __AWS_TLS__H__

typedef struct sslclient_context {
	bool init;
    int socket;
    
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
} sslclient_context;

/* Init SSL/TLS structure */
void aws_tls_init(sslclient_context *context);

/* Connect with certificates */
int aws_tls_connect(sslclient_context *context, const char *host, uint32_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);

/* Clean up resource */
void aws_tls_cleanup(sslclient_context *context);

/* Send data */
int aws_tls_send(sslclient_context *content, uint8_t* buf, uint16_t len);

/* Whether data is ready to receive. Must called before tls_receive */
int aws_tls_data_ready(sslclient_context *ssl_client);

/* Receive data */
int aws_tls_receive(sslclient_context *context, uint8_t* buf, uint16_t expect_len);

#endif
