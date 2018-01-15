#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include "aws_tls.h"
#define LOG_TAG "AWS_TLS"
#define LWIP_DEBUG
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE

#include <esp_log.h>
static int handle_mbedtls_error(int err)
{
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    ESP_LOGE(LOG_TAG, "%s", error_buf);
#endif
    ESP_LOGE(LOG_TAG, "MbedTLS message code: %d", err);
    return err;
}
void aws_tls_init(sslclient_context *ssl_client)
{
    mbedtls_ssl_init(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_init(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}
int aws_tls_connect(sslclient_context *ssl_client, const char *host, uint32_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key)
{
    const char *pers = "esp32-tls";
    char buf[512];
    int ret, flags, timeout;
    int enable = 1;
    int i = 0;

    struct in_addr  addr ;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    ssl_client->socket = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ssl_client->socket < 0)
    {
        ESP_LOGE(LOG_TAG ,"ERROR opening socket");
        return ssl_client->socket;
    }

    
    server = gethostbyname(host);
    if (server == NULL) 
    {
        ESP_LOGE(LOG_TAG, "gethostbyname failed");
        return -1;
    }

    while (server->h_addr_list[i] != 0)
    {
        addr.s_addr = *(u_long *)server->h_addr_list[i++];
        ESP_LOGD(LOG_TAG, "IP Address: %s\n", inet_ntoa(addr));
    }
    
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    
    serv_addr.sin_len = sizeof(struct sockaddr_in);
    serv_addr.sin_family = AF_INET;
    memcpy(&(serv_addr.sin_addr), &addr, sizeof(struct in_addr));
    serv_addr.sin_port = htons(port);

    ret = lwip_connect(ssl_client->socket, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));
    if (ret == 0) 
    {
        timeout = 30000;
        lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        lwip_setsockopt(ssl_client->socket, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
        lwip_setsockopt(ssl_client->socket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
        ESP_LOGD(LOG_TAG, "Socket connected");
    }
    else
    {
        ESP_LOGE(LOG_TAG, "Connect to Server failed! %d", ret);
        return -1;
    }
    
    fcntl( ssl_client->socket, F_SETFL, fcntl( ssl_client->socket, F_GETFL, 0 ) | O_NONBLOCK );



    ESP_LOGV(LOG_TAG, "Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);
    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *) pers, strlen(pers));
    if (ret < 0) 
    {
        return handle_mbedtls_error(ret);
    }




    ESP_LOGV(LOG_TAG, "Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        return handle_mbedtls_error(ret);
    }

    if (rootCABuff != NULL)
    {
        ESP_LOGV(LOG_TAG, "Loading CA cert");
        mbedtls_x509_crt_init(&ssl_client->ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        if (ret < 0)
        {
            return handle_mbedtls_error(ret);
        }
    }
    else
    {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        ESP_LOGI(LOG_TAG, "WARNING: Use certificates for a more secure communication!");
    }

    if (cli_cert != NULL && cli_key != NULL)
    {
        mbedtls_x509_crt_init(&ssl_client->client_cert);
        mbedtls_pk_init(&ssl_client->client_key);

        ESP_LOGV(LOG_TAG, "Loading CRT cert");
        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0) {
            return handle_mbedtls_error(ret);
        }


        ESP_LOGV(LOG_TAG, "Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);
        if (ret != 0) 
        {
            return handle_mbedtls_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }

    ESP_LOGV(LOG_TAG, "Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    if((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host)) != 0)
    {
        return handle_mbedtls_error(ret);
    }

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0)
    {
        return handle_mbedtls_error(ret);
    }

    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, &ssl_client->socket, mbedtls_net_send, mbedtls_net_recv, NULL );

    ESP_LOGV(LOG_TAG, "Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return handle_mbedtls_error(ret);
        }
        vTaskDelay(100);
    }

    ESP_LOGV(LOG_TAG, "SSL/TLS handshake done");
    
    if (cli_cert != NULL && cli_key != NULL)
    {
        ESP_LOGD(LOG_TAG, "Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0)
        {
            ESP_LOGD(LOG_TAG, "Record expansion is %d", ret);
        }
        else
        {
            ESP_LOGE(LOG_TAG, "Record expansion is unknown (compression)");
        }
    }



    ESP_LOGV(LOG_TAG, "Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0)
    {
        bzero(buf, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);

        ESP_LOGE(LOG_TAG, "Failed to verify peer certificate! verification info: %s", buf);

        aws_tls_cleanup(ssl_client);
        return handle_mbedtls_error(ret);
    }
    else
    {
        ESP_LOGV(LOG_TAG, "Certificate verified.");
    }
    

    /* Free some unused resource */
    if (rootCABuff != NULL)
    {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }

    if (cli_cert != NULL)
    {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }

    if (cli_key != NULL)
    {
        mbedtls_pk_free(&ssl_client->client_key);
    }    


    ESP_LOGI(LOG_TAG, "Secure channel created");

    ssl_client->init = true;
    return ssl_client->socket;
}



void aws_tls_cleanup(sslclient_context *ssl_client)
{
    ESP_LOGV(LOG_TAG, "Cleaning SSL connection.");

    ssl_client->init = false;
    if (ssl_client->socket >= 0)
    {
        close(ssl_client->socket);
        ssl_client->socket = -1;
    }

    mbedtls_ssl_free(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_free(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);
    mbedtls_entropy_free(&ssl_client->entropy_ctx);
}



int aws_tls_send(sslclient_context *ssl_client, uint8_t* buf, uint16_t len)
{
    ESP_LOGD(LOG_TAG, "Sending data");
    int ret = -1;

    while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, buf, len)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            return handle_mbedtls_error(ret);
        }
    }
    
    ESP_LOGD(LOG_TAG, "Sent %d bytes", ret);
    return ret;
}


int aws_tls_data_ready(sslclient_context *ssl_client)
{
    int ret, res;
    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
    res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0)
    {
        return handle_mbedtls_error(ret);
    }
    return res;
}


int aws_tls_receive(sslclient_context *ssl_client, uint8_t* buf, uint16_t rlen)
{
    ESP_LOGD(LOG_TAG, "Receiving data");

    int read = mbedtls_ssl_read(&ssl_client->ssl_ctx, buf, rlen);

    ESP_LOGD(LOG_TAG, "Received %d bytes", read);

    return read;
}