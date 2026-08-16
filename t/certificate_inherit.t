# vi:ft=

# Regression tests for the location-merge bug where a nested location's own
# sign_certificate/sign_certificate_key were silently ignored in favor of an
# already-resolved ancestor's ssl context (ngx_http_sign_merge_loc_conf
# copied conf->ssl = prev->ssl before checking whether this level defined
# its own certificate).

use lib 'lib';
use File::Temp qw(tempdir);
use Test::Nginx::Socket 'no_plan';

no_long_string();

my $cert_dir = tempdir(CLEANUP => 1);
system("openssl req -x509 -newkey rsa:2048 -nodes " .
    "-keyout $cert_dir/key.pem -out $cert_dir/cert.pem " .
    "-days 1 -subj '/CN=ngx_http_sign_module-test' " .
    "-batch >$cert_dir/openssl.log 2>&1") == 0
    or die "failed to generate self-signed test certificate: see $cert_dir/openssl.log";

$ENV{TEST_NGINX_CERT_DIR} = $cert_dir;

run_tests();

__DATA__

=== TEST 1: nested location overriding sign_certificate with its own (broken) certificate must not silently keep using the parent's already-resolved certificate
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_certificate $TEST_NGINX_CERT_DIR/cert.pem;
        sign_certificate_key $TEST_NGINX_CERT_DIR/key.pem;
        location /outer/inner {
            sign_certificate $TEST_NGINX_CERT_DIR/does-not-exist.pem;
            sign_certificate_key $TEST_NGINX_CERT_DIR/key.pem;
            return 200;
        }
    }
--- request
GET /outer/inner
--- must_die


=== TEST 2: nested location can override sign_certificate/sign_certificate_key with its own valid pair and still sign successfully
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_certificate $TEST_NGINX_CERT_DIR/cert.pem;
        sign_certificate_key $TEST_NGINX_CERT_DIR/key.pem;
        location /outer/inner {
            sign_certificate $TEST_NGINX_CERT_DIR/cert.pem;
            sign_certificate_key $TEST_NGINX_CERT_DIR/key.pem;
            sign_set $sig 'hello';
            return 200 $sig;
        }
    }
--- request
GET /outer/inner
--- error_code: 200
--- response_body_like: ^\S+$


=== TEST 3: nested location with no certificate of its own still inherits the parent's certificate and signs successfully (baseline, no regression)
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_certificate $TEST_NGINX_CERT_DIR/cert.pem;
        sign_certificate_key $TEST_NGINX_CERT_DIR/key.pem;
        location /outer/inner {
            sign_set $sig 'hello';
            return 200 $sig;
        }
    }
--- request
GET /outer/inner
--- error_code: 200
--- response_body_like: ^\S+$
