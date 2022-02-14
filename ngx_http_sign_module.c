#include <ndk.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t certificate;
    ngx_str_t certificate_key;
    ngx_array_t *password;
    ngx_ssl_t *ssl;
} ngx_http_sign_location_t;

ngx_module_t ngx_http_sign_module;

static char *ngx_http_sign_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_sign_location_t *location = conf;
    if (location->password != NGX_CONF_UNSET_PTR) return "is duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (!(location->password = ngx_ssl_read_password_file(cf, &elts[1]))) return "!ngx_ssl_read_password_file";
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_sign_func(ngx_http_request_t *r, ngx_str_t *val, ngx_http_variable_value_t *v) {
    ngx_http_sign_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_sign_module);
    if (!location->ssl) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!location->ssl"); return NGX_ERROR; }
    X509 *signcert = SSL_CTX_get0_certificate(location->ssl->ctx);
    if (!signcert) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!SSL_CTX_get0_certificate"); return NGX_ERROR; }
    EVP_PKEY *pkey = SSL_CTX_get0_privatekey(location->ssl->ctx);
    if (!pkey) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!SSL_CTX_get0_privatekey"); return NGX_ERROR; }
    ngx_str_t str = ngx_null_string;
    BIO *in = BIO_new_mem_buf(v->data, v->len);
    if (!in) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!BIO_new_mem_buf"); return NGX_ERROR; }
    PKCS7 *p7 = PKCS7_sign(signcert, pkey, NULL, in, PKCS7_BINARY|PKCS7_DETACHED);
    ngx_int_t rc = NGX_ERROR;
    if (!p7) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PKCS7_sign"); goto ret; }
    int len = ASN1_item_i2d((ASN1_VALUE *)p7, &str.data, ASN1_ITEM_rptr(PKCS7));
    if (len <= 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ASN1_item_i2d <= 0"); goto ret; }
    str.len = len;
    if (!(val->len = ngx_base64_encoded_length(str.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_base64_encoded_length"); goto ret; }
    if (!(val->data = ngx_pnalloc(r->pool, val->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); goto ret; }
    ngx_encode_base64(val, &str);
    rc = NGX_OK;
ret:
    if (p7) PKCS7_free(p7);
    if (in) BIO_free(in);
    if (str.data) free(str.data);
    return rc;
}

static ngx_command_t ngx_http_sign_commands[] = {
  { .name = ngx_string("sign_certificate"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_sign_location_t, certificate),
    .post = NULL },
  { .name = ngx_string("sign_certificate_key"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_sign_location_t, certificate_key),
    .post = NULL },
  { .name = ngx_string("sign_password_file"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_sign_ssl_password_file,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("sign_set"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ndk_set_var_value,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = &(ndk_set_var_t){ NDK_SET_VAR_VALUE, ngx_http_sign_func, 1, NULL } },
    ngx_null_command
};

static void *ngx_http_sign_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_sign_location_t *location = ngx_pcalloc(cf->pool, sizeof(*location));
    if (!location) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    location->password = NGX_CONF_UNSET_PTR;
    return location;
}

static ngx_int_t ngx_http_sign_set_ssl(ngx_conf_t *cf, ngx_http_sign_location_t *location) {
    if (!(location->ssl = ngx_pcalloc(cf->pool, sizeof(*location->ssl)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    location->ssl->log = cf->log;
    if (ngx_ssl_create(location->ssl, 0, NULL) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_ssl_create != NGX_OK"); return NGX_ERROR; }
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_ssl_cleanup_ctx(location->ssl); ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = location->ssl;
    if (location->certificate.len) {
        if (location->certificate_key.len == 0) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no \"sign_certificate_key\" is defined for certificate \"%V\"", &location->certificate); return NGX_ERROR; }
        if (ngx_ssl_certificate(cf, location->ssl, &location->certificate, &location->certificate_key, location->password == NGX_CONF_UNSET_PTR ? NULL : location->password) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_ssl_certificate != NGX_OK"); return NGX_ERROR; }
    }
    return NGX_OK;
}

static char *ngx_http_sign_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_sign_location_t *prev = parent;
    ngx_http_sign_location_t *conf = child;
    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_ptr_value(conf->password, prev->password, NGX_CONF_UNSET_PTR);
    if (!conf->ssl) conf->ssl = prev->ssl;
    if (!conf->certificate.len) return NGX_CONF_OK;
    if (conf->ssl) return NGX_CONF_OK;
    if (ngx_http_sign_set_ssl(cf, conf) != NGX_OK) return "ngx_http_sign_set_ssl != NGX_OK";
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_sign_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_sign_create_loc_conf,
    .merge_loc_conf = ngx_http_sign_merge_loc_conf
};

ngx_module_t ngx_http_sign_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_sign_ctx,
    .commands = ngx_http_sign_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
