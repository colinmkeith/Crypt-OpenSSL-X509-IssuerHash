/* vim: set foldmethod=marker filetype=xs: */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

/* OpenSSL-0.9.3a has some strange warning about this in
 *    openssl/des.h
 */
#undef _

#include <errno.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>

#define MODULUS_LENGTH 256

#define KEY_TYPE 0
#define CERT_TYPE 1
#define CSR_TYPE 2

char errtype = 0;



// {{{ void *load_pem(const char *file, char type)
void *load_pem(const char *file, char type){
  BIO *data = NULL;

  if((data=BIO_new(BIO_s_file())) == NULL){
    errtype = 1;
    return NULL;
  }

  if(BIO_read_filename(data, file) <= 0){
    BIO_free(data);
    errtype = -1;
    return NULL;
  }

  // {{{ Key:
  if(type == KEY_TYPE){
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(data, NULL, NULL, NULL);
    BIO_free(data);

    if(pkey == NULL){
      errtype = -1;
      return NULL;
    }

    return (EVP_PKEY *)pkey;
  } // }}}

  // {{{ CSR
  else if(type == CSR_TYPE) {
    X509_REQ *x = PEM_read_bio_X509_REQ(data, NULL, NULL, NULL);
    BIO_free(data);

    if(x == NULL){
      errtype = -1;
      return NULL;
    }

    return (X509_REQ *)x;
  } // }}}

  // {{{ Cert
  else {
    X509 *x = PEM_read_bio_X509_AUX(data, NULL, NULL, NULL);
    BIO_free(data);

    if(x == NULL){
      errtype = -1;
      return NULL;
    }

    return (X509 *)x;
  } // }}}

  return NULL;
} // }}}


MODULE = Crypt::OpenSSL::X509::IssuerHash    PACKAGE = Crypt::OpenSSL::X509::IssuerHash

# /* {{{ get_cert_hash($file, $type) */
SV *
get_cert_hash(file, type);
    int type;
    char *file;
  CODE:
    char *buf = NULL;
    X509 *x = (X509 *)load_pem(file, 1);

    # // Initialise stack as an empty mortal value, e.g. undef:
    ST(0) = sv_newmortal();

    if(x == NULL)
      XSRETURN(0);

    if((buf = (char *)calloc(82, sizeof(char))) == NULL){
      errtype = 0;
      X509_free(x);
      XSRETURN(0);
    }

    if(type == 0)
      snprintf(buf, 81, "%08lx", X509_issuer_name_hash(x));
    else
      snprintf(buf, 81, "%08lx", X509_subject_name_hash(x));

    ST(0) = sv_2mortal(newSVpv(buf, 0));

    free(buf);
    X509_free(x);
# /* # }}} */

# /* {{{ get_certhash_error() */
SV *
get_certhash_error()
  INIT:
    char *buf = NULL;
  CODE:

    # // Initialise stack as an empty mortal value, e.g. undef:
    ST(0) = sv_newmortal();

    if(errtype == 0)
      XSRETURN(0);

    if((buf = (char *)calloc(1024, sizeof(char))) == NULL){
      croak("Cannot malloc buffer");
      XSRETURN(0);
    }

    if(errtype == 1){
      snprintf(buf, 990, "Error allocating memory: %s", strerror(errno));
    } else if(errtype == -1){
      ERR_load_crypto_strings();
      ERR_error_string_n(ERR_get_error(), buf, 1023);
    } else {
      strncpy(buf, "Unknown error type", 1023);
    }
    ST(0) = sv_2mortal(newSVpv(buf, 0));
    free(buf);
# /* }}} */

# /* {{{ get_modulus(file, [type]) */
SV *
get_modulus(file, ...)
  char *file;
  INIT:
    int type;
    RSA *rsa;
    EVP_PKEY *pkey;
  CODE:
    // Initialise stack as an empty mortal value, e.g. undef:
    ST(0) = sv_newmortal();

    // {{{ You can call it without a value
    type = 1;
    if(items == 2){
      type = (int)SvNV(ST(1));
    } else if(strcmp(file + strlen(file)-4, ".crt") == 0){
      type = CERT_TYPE;
    } else if(strcmp(file + strlen(file)-4, ".csr") == 0){
      type = CSR_TYPE;
    } else if(strcmp(file + strlen(file)-4, ".key") == 0){
      type = KEY_TYPE;
    } else {
      warn("get_modulus(): No type defined, and unknown filetype, "\
           "defaulting to a cert\n");
    } // }}}

    // {{{ Modulus for the key:
    if(type == KEY_TYPE) {
      if((pkey = (EVP_PKEY *)load_pem(file, KEY_TYPE)) == NULL)
        XSRETURN(0); // undef?
    } // }}}

    // {{{ Modulus for a CSR:
    else if(type == CSR_TYPE) {
      X509_REQ *x = (X509_REQ *)load_pem(file, CSR_TYPE);
      if(x == NULL)
        XSRETURN(0);

      if((pkey = X509_REQ_get_pubkey(x)) == NULL){
        errtype = -1;
        X509_REQ_free(x);
        XSRETURN(0);
      }
      X509_REQ_free(x);
    } // }}}

    // {{{ Modulus for Cert:
    else {
      X509 *x = (X509 *)load_pem(file, CERT_TYPE);
      if(x == NULL)
        XSRETURN(0);

      if((pkey = X509_get_pubkey(x)) == NULL){
        errtype = -1;
        X509_free(x);
        XSRETURN(0);
      }
      X509_free(x);
    } // }}}

    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL){
      errtype = -1;
      EVP_PKEY_free(pkey);
      XSRETURN(0);
    }
    EVP_PKEY_free(pkey);

    if(rsa != NULL){
      ST(0) = sv_2mortal(newSVpv(BN_bn2hex(rsa->n), 0));
      RSA_free(rsa);
    }
# /* }}} */

# /* {{{ get_cert_name($cert) */
SV *
get_cert_name(cert, type)
  int type;
  char *cert;
  INIT:
    int i;
    int n;
    char *s;
    char *buf;
    AV *tmpr;
    X509 *x = NULL;
    X509_NAME *a = NULL;
    X509_NAME_ENTRY *ne = NULL;
  CODE:
    # // Initialise stack as an empty mortal value, e.g. undef:
    ST(0) = sv_newmortal();

    if((x = (X509 *)load_pem(cert, 1)) == NULL)
      XSRETURN(0);

    if((buf = (char *)calloc(1024, sizeof(char))) == NULL){
      errtype = 0;
      X509_free(x);
      XSRETURN(0);
    }


# // X509_NAME_free(n)

    if(type == 0){
      if(X509_NAME_oneline(X509_get_issuer_name(x), buf, 1023) == 0){
        errtype = -1;
        X509_free(x);
        free(buf);
        XSRETURN(0);
      }
    } else {
      if(X509_NAME_oneline(X509_get_subject_name(x), buf, 1023) == 0){
        errtype = -1;
        X509_free(x);
        free(buf);
        XSRETURN(0);
      }
    }

    ST(0) = sv_2mortal(newSVpv(buf, 0));
    X509_free(x);
    free(buf);
# /* }}} */

# /* {{{ get_cert_validity($cert) */
SV *
get_cert_validityint(cert);
  char *cert;
  INIT:
    char *buf;
    X509 *x;
  PPCODE:
    # // Initialise stack as an empty mortal value, e.g. undef:
    ST(0) = sv_newmortal();

    if((x = (X509 *)load_pem(cert, 1)) == NULL)
      XSRETURN(0);

    if((buf = (char *)calloc(1024, sizeof(char))) == NULL){
      errtype = 0;
      X509_free(x);
      XSRETURN(0);
    }

    // I know that I'm returning two values, so:
    EXTEND(SP, 2);
    strncpy(buf, (char *)((ASN1_TIME *)X509_get_notBefore(x))->data, 1023);
    PUSHs(sv_2mortal(newSVpv(buf, 0)));
    strncpy(buf, (char *)((ASN1_TIME *)X509_get_notAfter(x))->data, 1023);
    PUSHs(sv_2mortal(newSVpv(buf, 0)));
    X509_free(x);
    free(buf);
# /* }}} */

# /* {{{ check_cert_validity($cert) */
SV *
check_cert_validity(cert);
  char *cert;
  INIT:
    X509 *x;
    time_t now;
  CODE:
    # // Initialise stack as an empty mortal value, e.g. undef:
    ST(0) = sv_newmortal();

    if((x = (X509 *)load_pem(cert, 1)) == NULL)
      XSRETURN(0);

    now = time(NULL);
    if(X509_cmp_time(X509_get_notBefore(x), &now) > 0){
      sv_setnv(ST(0), 1);
    } else if(X509_cmp_time(X509_get_notAfter(x), &now) < 0){
      sv_setnv(ST(0), -1);
    } else {
      sv_setnv(ST(0), 0);
    }
    X509_free(x);
# /* }}} */
