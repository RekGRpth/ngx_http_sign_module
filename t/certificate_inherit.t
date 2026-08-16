# vi:ft=

# Tests for ngx_http_sign_module: the location-merge bug where a nested
# location's own sign_certificate/sign_certificate_key were silently ignored
# in favor of an already-resolved ancestor's ssl context (TEST 1-3), plus
# config-time directive validation and the sign_password_file directive
# (TEST 4-9).

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

system("openssl req -x509 -newkey rsa:2048 -cipher aes-256-cbc -passout pass:testpass123 " .
    "-keyout $cert_dir/enc-key.pem -out $cert_dir/enc-cert.pem " .
    "-days 1 -subj '/CN=ngx_http_sign_module-test-encrypted' " .
    "-batch >>$cert_dir/openssl.log 2>&1") == 0
    or die "failed to generate encrypted test certificate: see $cert_dir/openssl.log";

open(my $pwfh, '>', "$cert_dir/password.txt")
    or die "failed to write password file: $!";
print $pwfh "testpass123\n";
close $pwfh;

$ENV{TEST_NGINX_CERT_DIR} = $cert_dir;

run_tests();

__DATA__

=== TEST 1: nested location overriding sign_certificate with its own (broken) certificate must not silently keep using the parent's already-resolved certificate
--- main_config
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


=== TEST 4: sign_certificate without a matching sign_certificate_key fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_certificate $TEST_NGINX_CERT_DIR/cert.pem;
        return 200;
    }
--- request
GET /outer
--- must_die
--- error_log
no "sign_certificate_key" is defined for certificate


=== TEST 5: sign_set with a variable name missing the leading $ fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_set sig 'hello';
        return 200;
    }
--- request
GET /outer
--- must_die
--- error_log
invalid variable name


=== TEST 6: sign_set with a syntactically broken complex value fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_set $sig "${";
        return 200;
    }
--- request
GET /outer
--- must_die


=== TEST 7: sign_password_file given twice in the same location fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_password_file $TEST_NGINX_CERT_DIR/password.txt;
        sign_password_file $TEST_NGINX_CERT_DIR/password.txt;
        return 200;
    }
--- request
GET /outer
--- must_die
--- error_log
is duplicate


=== TEST 8: sign_set with no sign_certificate anywhere in the location chain yields an empty value instead of crashing
--- main_config
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_set $sig 'hello';
        return 200 "[$sig]";
    }
--- request
GET /outer
--- error_code: 200
--- response_body chomp
[]


=== TEST 9: sign_password_file correctly decrypts an AES-encrypted certificate_key and signs successfully
--- main_config
    load_module /etc/nginx/modules/ngx_http_sign_module.so;
--- config
    location /outer {
        sign_certificate $TEST_NGINX_CERT_DIR/enc-cert.pem;
        sign_certificate_key $TEST_NGINX_CERT_DIR/enc-key.pem;
        sign_password_file $TEST_NGINX_CERT_DIR/password.txt;
        sign_set $sig 'hello';
        return 200 $sig;
    }
--- request
GET /outer
--- error_code: 200
--- response_body_like: ^\S+$
