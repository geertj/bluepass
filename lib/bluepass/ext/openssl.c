/*
 * This file is part of Bluepass. Bluepass is Copyright (c) 2012
 * Geert Jansen. All rights are reserved.
 */

#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>


static PyObject *openssl_Error = NULL;


#define RETURN_ERROR(fmt, ...) \
    do { \
        if ((fmt) != NULL) PyErr_Format(openssl_Error, fmt, ## __VA_ARGS__); \
        goto error; \
    } while (0)

#define CHECK_ERROR(cond, fmt, ...) \
    do { if (cond) { RETURN_ERROR(fmt, ## __VA_ARGS__); } } while (0)

#define CHECK_OPENSSL_ERROR(cond) \
    CHECK_ERROR(cond, ERR_error_string(ERR_get_error(), NULL))

#define CHECK_PYTHON_ERROR(cond) \
    CHECK_ERROR(cond, NULL)

#define MALLOC(var, size) \
    do { if ((var = malloc(size)) == NULL) { \
        PyErr_NoMemory(); \
        RETURN_ERROR(NULL); \
    } } while (0)

#define REALLOC(var, size) \
    do { \
        void *_ptr = var; \
        MALLOC(var, size*2); \
        memcpy(var, _ptr, size); \
        clear_free(_ptr, size); \
        size = size*2; \
    } while (0)

#define ASSERT(cond) \
    do { if (!(cond)) { \
        PyErr_SetString(PyExc_AssertionError, "assertion failed " #cond); \
        RETURN_ERROR(NULL); \
    } } while (0)

#define OPENSSL_clear_free(ptr, len) \
    do { if ((ptr) != NULL) { \
        if ((len) > 0) memset((ptr), 0, (len)); \
        OPENSSL_free(ptr); \
    } } while (0)

#define clear_free(ptr, len) \
    do { if ((ptr) != NULL) { \
        if ((len) > 0) memset((ptr), 0, (len)); \
        free(ptr); \
    } } while (0)

#define RSA_clear_free RSA_free
#define DH_clear_free DH_free

#define PyString_ClearFree(s) \
    do { if (s != NULL) { \
        PyStringObject *_s = (PyStringObject *) s; \
        if (_s->ob_sval && _s->ob_size > 0) \
            memset(_s->ob_sval, 0, _s->ob_size); \
        Py_DECREF(s); \
    } } while (0)


static PyObject *
openssl_rsa_genkey(PyObject *self, PyObject *args)
{
    unsigned char *privkey = NULL, *pubkey = NULL;
    int bits, ret, privlen = 0, publen = 0;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;
    PyObject *Presult = NULL, *Pprivkey = NULL, *Ppubkey = NULL;

    if (!PyArg_ParseTuple(args, "i:rsa_genkey", &bits))
        return NULL;

    e = BN_new();
    CHECK_OPENSSL_ERROR(e == NULL);
    ret = BN_set_word(e, RSA_F4);
    CHECK_OPENSSL_ERROR(ret != 1);
    rsa = RSA_new();
    CHECK_OPENSSL_ERROR(rsa == NULL);

    while (1)
    {
        Py_BEGIN_ALLOW_THREADS
        ret = RSA_generate_key_ex(rsa, bits, e, NULL);
        Py_END_ALLOW_THREADS
        CHECK_OPENSSL_ERROR(ret != 1);
        ret = RSA_check_key(rsa);
        CHECK_OPENSSL_ERROR(ret < 0);
        if (ret == 1)
            break;
    }

    privlen = i2d_RSAPrivateKey(rsa, &privkey);
    CHECK_OPENSSL_ERROR(privlen <= 0);
    publen = i2d_RSAPublicKey(rsa, &pubkey);
    CHECK_OPENSSL_ERROR(publen <= 0);

    Presult = PyTuple_New(2);
    CHECK_PYTHON_ERROR(Presult == NULL);
    Pprivkey = PyString_FromStringAndSize((char *) privkey, privlen);
    CHECK_PYTHON_ERROR(Pprivkey == NULL);
    Ppubkey = PyString_FromStringAndSize((char *) pubkey, publen);
    CHECK_PYTHON_ERROR(Ppubkey == NULL);
    PyTuple_SET_ITEM(Presult, 0, Pprivkey);
    PyTuple_SET_ITEM(Presult, 1, Ppubkey);
    goto cleanup;

error:
    Py_XDECREF(Presult);
    PyString_ClearFree(Pprivkey);
    PyString_ClearFree(Ppubkey);

cleanup:
    RSA_clear_free(rsa);
    BN_clear_free(e);
    OPENSSL_clear_free(privkey, privlen);
    OPENSSL_clear_free(pubkey, publen);
    return Presult;
}

static PyObject *
openssl_rsa_checkkey(PyObject *self, PyObject *args)
{
    unsigned char *key;
    int keylen, check;
    RSA *rsa = NULL;
    PyObject *Presult = NULL;

    if (!PyArg_ParseTuple(args, "s#:rsa_size", &key, &keylen))
        return NULL;

    rsa = d2i_RSAPublicKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    check = RSA_check_key(rsa);
    CHECK_OPENSSL_ERROR(check < 0);
    Presult = PyBool_FromLong(check == 1);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    RSA_clear_free(rsa);
    return Presult;
}

static PyObject *
openssl_rsa_size(PyObject *self, PyObject *args)
{
    unsigned char *key;
    int keylen;
    RSA *rsa = NULL;
    PyObject *Presult = NULL;

    if (!PyArg_ParseTuple(args, "s#:rsa_size", &key, &keylen))
        return NULL;

    rsa = d2i_RSAPublicKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    Presult = PyInt_FromLong(RSA_size(rsa) * 8);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    RSA_clear_free(rsa);
    return Presult;
}

static PyObject *
openssl_rsa_encrypt(PyObject *self, PyObject *args)
{
    char *padding;
    unsigned char *in, *key, *out = NULL;
    int inlen, outlen, keylen, size;
    RSA *rsa = NULL;
    PyObject *Pout = NULL;

    if (!PyArg_ParseTuple(args, "s#s#s:rsa_encrypt", &in, &inlen,
                          &key, &keylen, &padding))
        return NULL;
    if (strcmp(padding, "oaep"))
        RETURN_ERROR("unsupported padding: %s", padding);

    rsa = d2i_RSAPublicKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    outlen = RSA_size(rsa);
    MALLOC(out, outlen);
    size = RSA_public_encrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
    CHECK_OPENSSL_ERROR(size <= 0);
    Pout = PyString_FromStringAndSize((char *) out, size);
    CHECK_PYTHON_ERROR(Pout == NULL);

error:
    RSA_clear_free(rsa);
    clear_free(out, outlen);
    return Pout;
}

static PyObject *
openssl_rsa_decrypt(PyObject *self, PyObject *args)
{
    char *padding;
    unsigned char *in, *key, *out = NULL;
    int inlen, outlen, keylen, size;
    RSA *rsa = NULL;
    PyObject *Pout = NULL;

    if (!PyArg_ParseTuple(args, "s#s#s:rsa_decrypt", &in, &inlen,
                          &key, &keylen, &padding))
        return NULL;
    if (strcmp(padding, "oaep"))
        RETURN_ERROR("unsupported padding: %s", padding);

    rsa = d2i_RSAPrivateKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    outlen = RSA_size(rsa);
    MALLOC(out, outlen);
    size = RSA_private_decrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
    CHECK_OPENSSL_ERROR(size < 0);
    Pout = PyString_FromStringAndSize((char *) out, size);
    CHECK_PYTHON_ERROR(Pout == NULL);

error:
    RSA_clear_free(rsa);
    clear_free(out, outlen);
    return Pout;
}

static PyObject *
openssl_rsa_sign(PyObject *self, PyObject *args)
{
    char *padding;
    unsigned char *in, *key, *sig = NULL, *em = NULL, *md = NULL;
    int inlen, keylen, siglen, emlen, size, ret, mdlen;
    PyObject *Psig = NULL;
    RSA *rsa = NULL;
    const EVP_MD *digest;
    EVP_MD_CTX ctx;

    if (!PyArg_ParseTuple(args, "s#s#s:rsa_sign", &in, &inlen,
                          &key, &keylen, &padding))
        return NULL;
    if (strncmp(padding, "pss-", 4))
        RETURN_ERROR("unsupported padding: %s", padding);
    if ((digest = EVP_get_digestbyname(padding+4)) == NULL)
        RETURN_ERROR("unknown hash function in: %s", padding);

    mdlen = EVP_MD_size(digest);
    MALLOC(md, mdlen);
    EVP_MD_CTX_init(&ctx);
    ret = EVP_DigestInit(&ctx, digest);
    CHECK_OPENSSL_ERROR(ret != 1);
    ret = EVP_DigestUpdate(&ctx, in, inlen);
    CHECK_OPENSSL_ERROR(ret != 1);
    ret = EVP_DigestFinal(&ctx, md, NULL);
    CHECK_OPENSSL_ERROR(ret != 1);

    rsa = d2i_RSAPrivateKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    emlen = RSA_size(rsa);
    MALLOC(em, emlen);
    ret = RSA_padding_add_PKCS1_PSS(rsa, em, md, digest, mdlen);
    CHECK_OPENSSL_ERROR(ret != 1);
    siglen = RSA_size(rsa);
    MALLOC(sig, siglen);
    size = RSA_private_encrypt(RSA_size(rsa), em, sig, rsa, RSA_NO_PADDING);
    CHECK_OPENSSL_ERROR(size <= 0);
    Psig = PyString_FromStringAndSize((char *) sig, size);
    CHECK_PYTHON_ERROR(Psig == NULL);

error:
    RSA_clear_free(rsa);
    clear_free(md, mdlen);
    clear_free(em, emlen);
    clear_free(sig, siglen);
    return Psig;
}

static PyObject *
openssl_rsa_verify(PyObject *self, PyObject *args)
{
    char *padding;
    unsigned char *in, *sig, *key, *em = NULL, *md = NULL;
    int inlen, siglen, keylen, emlen, mdlen, ret;
    PyObject *Presult = NULL;
    RSA *rsa = NULL;
    EVP_MD_CTX ctx;
    const EVP_MD *digest;

    if (!PyArg_ParseTuple(args, "s#s#s#s:rsa_verify", &in, &inlen,
                          &sig, &siglen, &key, &keylen, &padding))
        return NULL;
    if (strncmp(padding, "pss-", 4))
        RETURN_ERROR("unsupported padding: %s", padding);
    if ((digest = EVP_get_digestbyname(padding+4)) == NULL)
        RETURN_ERROR("unknown hash function in: %s", padding);

    mdlen = EVP_MD_size(digest);
    MALLOC(md, mdlen);
    EVP_MD_CTX_init(&ctx);
    ret = EVP_DigestInit(&ctx, digest);
    CHECK_OPENSSL_ERROR(ret != 1);
    ret = EVP_DigestUpdate(&ctx, in, inlen);
    CHECK_OPENSSL_ERROR(ret != 1);
    ret = EVP_DigestFinal(&ctx, md, NULL);
    CHECK_OPENSSL_ERROR(ret != 1);

    rsa = d2i_RSAPublicKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    emlen = RSA_size(rsa);
    MALLOC(em, emlen);
    emlen = RSA_public_decrypt(siglen, sig, em, rsa, RSA_NO_PADDING);
    CHECK_OPENSSL_ERROR(emlen <= 0);
    ret = RSA_verify_PKCS1_PSS(rsa, md, digest, em, mdlen);
    CHECK_OPENSSL_ERROR(ret < 0);
    Presult = PyBool_FromLong(ret);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    RSA_clear_free(rsa);
    clear_free(md, mdlen);
    clear_free(em, emlen);
    return Presult;
}

static PyObject *
openssl_dh_genparams(PyObject *self, PyObject *args)
{
    unsigned char *params = NULL;
    int bits, generator, size = 0, check, ret;
    DH *dh = NULL;
    PyObject *Pparams = NULL;

    if (!PyArg_ParseTuple(args, "ii:dh_genparams", &bits, &generator))
        return NULL;

    dh = DH_new();
    CHECK_OPENSSL_ERROR(dh == NULL);
    while (1)
    {
        Py_BEGIN_ALLOW_THREADS
        ret = DH_generate_parameters_ex(dh, bits, generator, NULL);
        Py_END_ALLOW_THREADS
        CHECK_OPENSSL_ERROR(ret != 1);
        ret = DH_check(dh, &check);
        CHECK_OPENSSL_ERROR(ret != 1);
        if (check == 0)
            break;
    }
    size = i2d_DHparams(dh, &params);
    CHECK_OPENSSL_ERROR(size <= 0);
    Pparams = PyString_FromStringAndSize((char *) params, size);
    CHECK_PYTHON_ERROR(Pparams == NULL);

error:
    DH_clear_free(dh);
    OPENSSL_clear_free(params, size);
    return Pparams;
}

static PyObject *
openssl_dh_checkparams(PyObject *self, PyObject *args)
{
    unsigned char *params;
    int paramslen, ret, check;
    DH *dh = NULL;
    PyObject *Presult = NULL;

    if (!PyArg_ParseTuple(args, "s#:dh_checkparams", &params, &paramslen))
        return NULL;

    dh = d2i_DHparams(NULL, (const unsigned char **) &params, paramslen);
    CHECK_OPENSSL_ERROR(dh == NULL);
    ret = DH_check(dh, &check);
    CHECK_OPENSSL_ERROR(ret != 1);
    Presult = PyBool_FromLong(check == 0);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    DH_clear_free(dh);
    return Presult;
}

static PyObject *
openssl_dh_size(PyObject *self, PyObject *args)
{
    unsigned char *params;
    int paramslen, nbytes;
    DH *dh = NULL;
    PyObject *Presult = NULL;

    if (!PyArg_ParseTuple(args, "s#:dh_size", &params, &paramslen))
        return NULL;

    dh = d2i_DHparams(NULL, (const unsigned char **) &params, paramslen);
    CHECK_OPENSSL_ERROR(dh == NULL);

    nbytes = DH_size(dh);
    CHECK_OPENSSL_ERROR(nbytes < 0);
    Presult = PyInt_FromLong(nbytes * 8);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    DH_clear_free(dh);
    return Presult;
}

static PyObject *
openssl_dh_genkey(PyObject *self, PyObject *args)
{
    unsigned char *params, *privkey = NULL, *pubkey = NULL;
    int paramslen, ret, privlen = 0, publen = 0;
    DH *dh = NULL;
    PyObject *Presult = NULL, *Pprivkey = NULL, *Ppubkey = NULL;

    if (!PyArg_ParseTuple(args, "s#:dh_genkey", &params, &paramslen))
        return NULL;

    dh = d2i_DHparams(NULL, (const unsigned char **) &params, paramslen);
    CHECK_OPENSSL_ERROR(dh == NULL);

    ret = DH_generate_key(dh);
    CHECK_OPENSSL_ERROR(ret == 0);
    MALLOC(privkey, BN_num_bytes(dh->priv_key));
    privlen = BN_bn2bin(dh->priv_key, privkey);
    MALLOC(pubkey, BN_num_bytes(dh->pub_key));
    publen = BN_bn2bin(dh->pub_key, pubkey);

    Presult = PyTuple_New(2);
    CHECK_PYTHON_ERROR(Presult == NULL);
    Pprivkey = PyString_FromStringAndSize((char *) privkey, privlen);
    CHECK_PYTHON_ERROR(Pprivkey == NULL);
    Ppubkey = PyString_FromStringAndSize((char *) pubkey, publen);
    CHECK_PYTHON_ERROR(Ppubkey == NULL);
    PyTuple_SET_ITEM(Presult, 0, Pprivkey);
    PyTuple_SET_ITEM(Presult, 1, Ppubkey);
    goto cleanup;

error:
    Py_XDECREF(Presult);
    PyString_ClearFree(Pprivkey);
    PyString_ClearFree(Ppubkey);

cleanup:
    DH_clear_free(dh);
    clear_free(privkey, privlen);
    clear_free(pubkey, publen);
    return Presult;
}

static PyObject *
openssl_dh_checkkey(PyObject *self, PyObject *args)
{
    unsigned char *params, *pubkey;
    int paramslen, publen, ret, check;
    BIGNUM *bn = NULL;
    DH *dh = NULL;
    PyObject *Presult = NULL;

    if (!PyArg_ParseTuple(args, "s#s#:dh_checkkey", &params, &paramslen,
                          &pubkey, &publen))
        return NULL;

    dh = d2i_DHparams(NULL, (const unsigned char **) &params, paramslen);
    CHECK_OPENSSL_ERROR(dh == NULL);
    bn = BN_bin2bn(pubkey, publen, NULL);
    CHECK_OPENSSL_ERROR(bn == NULL);
    ret = DH_check_pub_key(dh, bn, &check);
    CHECK_OPENSSL_ERROR(ret != 1);
    Presult = PyBool_FromLong(check == 0);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    DH_clear_free(dh);
    BN_clear_free(bn);
    return Presult;
}

static PyObject *
openssl_dh_compute(PyObject *self, PyObject *args)
{
    unsigned char *params, *privkey, *pubkey, *secret = NULL;
    int paramslen, privlen, publen, seclen, size;
    BIGNUM *bn = NULL;
    DH *dh = NULL;
    PyObject *Presult = NULL;

    if (!PyArg_ParseTuple(args, "s#s#s#:dh_compute", &params, &paramslen,
                          &privkey, &privlen, &pubkey, &publen))
            return NULL;

    dh = d2i_DHparams(NULL, (const unsigned char **) &params, paramslen);
    CHECK_OPENSSL_ERROR(dh == NULL);

    dh->priv_key = BN_bin2bn(privkey, privlen, NULL);
    CHECK_OPENSSL_ERROR(dh->priv_key == NULL);
    bn = BN_bin2bn(pubkey, publen, NULL);
    CHECK_OPENSSL_ERROR(bn == NULL);

    seclen = DH_size(dh);
    MALLOC(secret, seclen);
    size = DH_compute_key(secret, bn, dh);
    if (size < seclen) {
        /* prepend a short secret with zeros.
         * see: http://www.qacafe.com/static/pdf/ike_whitepaper.pdf */
        memmove(secret+seclen-size, secret, size);
        memset(secret, 0, seclen-size);
        size = seclen;
    }
    CHECK_OPENSSL_ERROR(size <= 0);
    Presult = PyString_FromStringAndSize((char *) secret, size);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    DH_clear_free(dh);
    BN_clear_free(bn);
    clear_free(secret, seclen);
    return Presult;
}

static PyObject *
openssl_aes_encrypt(PyObject *self, PyObject *args)
{
    char *mode;
    unsigned char *in, *pad = NULL, *out = NULL, *iv, *iv2 = NULL, *ukey;
    int inlen, padlen, outlen, ukeylen, ivlen, i, ret;
    AES_KEY key;
    PyObject *Pout = NULL;

    if (!PyArg_ParseTuple(args, "s#s#s#s:aes_encrypt", &in, &inlen,
                          &ukey, &ukeylen, &iv, &ivlen, &mode))
        return NULL;
    if ((ukeylen != 16) && (ukeylen != 24) && (ukeylen != 32))
        RETURN_ERROR("key size must be 128, 192 or 256 bits");
    if (ivlen != 16)
        RETURN_ERROR("IV must be 128 bits");
    if (strcmp(mode, "cbc-pkcs7"))
        RETURN_ERROR("unsupported mode: %s", mode);

    ret = AES_set_encrypt_key(ukey, ukeylen*8, &key);
    CHECK_OPENSSL_ERROR(ret != 0);

    padlen = (16 - inlen%16);
    outlen = inlen+padlen;
    MALLOC(pad, outlen);
    memcpy(pad, in, inlen);
    for (i=0; i<padlen; i++)
        pad[inlen+i] = (char) padlen;
    MALLOC(out, outlen);
    MALLOC(iv2, ivlen); // AES_cbc_encrypt modifies the IV
    memcpy(iv2, iv, ivlen);

    AES_cbc_encrypt(pad, out, outlen, &key, iv2, 1);
    Pout = PyString_FromStringAndSize((char *) out, outlen);
    CHECK_PYTHON_ERROR(Pout == NULL);

error:
    clear_free(pad, outlen);
    clear_free(out, outlen);
    clear_free(iv2, ivlen);
    return Pout;
}

static PyObject *
openssl_aes_decrypt(PyObject *self, PyObject *args)
{
    char *mode;
    unsigned char *in, *out = NULL, *iv, *iv2 = NULL, *ukey;
    int inlen, ukeylen, ivlen, padlen, i, ret;
    AES_KEY key;
    PyObject *Pout = NULL;

    if (!PyArg_ParseTuple(args, "s#s#s#s:aes_decrypt", &in, &inlen,
                          &ukey, &ukeylen, &iv, &ivlen, &mode))
        return NULL;
    if ((inlen == 0) || (inlen % 16))
        RETURN_ERROR("invalid padding");
    if ((ukeylen != 16) && (ukeylen != 24) && (ukeylen != 32))
        RETURN_ERROR("key size must be 128, 192 or 256 bits");
    if (ivlen != 16)
        RETURN_ERROR("IV must be 128 bits");
    if (strcmp(mode, "cbc-pkcs7"))
        RETURN_ERROR("unsupported mode: %s", mode);

    ret = AES_set_decrypt_key(ukey, ukeylen*8, &key);
    CHECK_OPENSSL_ERROR(ret != 0);

    MALLOC(out, inlen);
    MALLOC(iv2, ivlen);
    memcpy(iv2, iv, ivlen);

    AES_cbc_encrypt(in, out, inlen, &key, iv, 0);

    padlen = out[inlen-1];
    if (padlen > 16)
        RETURN_ERROR("invalid padding 1: %s", out);
    for (i=0; i<padlen; i++)
        if (out[inlen-1-i] != padlen)
            RETURN_ERROR("invalid padding 2: %s", out);
    Pout = PyString_FromStringAndSize((char *) out, inlen-padlen);
    CHECK_PYTHON_ERROR(Pout == NULL);

error:
    clear_free(out, inlen);
    clear_free(iv2, ivlen);
    return Pout;
}

static PyObject *
openssl_pbkdf2(PyObject *self, PyObject *args)
{
    char *prf, *password;
    unsigned char *salt, *out = NULL;
    int pwlen, slen, iter, keylen, ret;
    PyObject *Presult = NULL;
#if OPENSSL_VERSION >= 0x10000000
    const EVP_MD *digest;
#endif

    if (!PyArg_ParseTuple(args, "s#s#iis:pbkdf2", &password, &pwlen,
                          &salt, &slen, &iter, &keylen, &prf))
        return NULL;

    if ((pwlen == 0) || (slen == 0))
        RETURN_ERROR("password and salt must be > 0 characters");
    if (iter == 0)
        RETURN_ERROR("iter must be > 0");
    if (strncmp(prf, "hmac-", 5))
        RETURN_ERROR("unsupported pseudo-random function: %s", prf);

#if OPENSSL_VERSION >= 0x10000000
    if ((digest = EVP_get_digestbyname(prf+5)) == NULL)
        RETURN_ERROR("unknown hash function in: %s", prf);

    MALLOC(out, keylen);
    Py_BEGIN_ALLOW_THREADS
    ret = PKCS5_PBKDF2_HMAC(password, pwlen, salt, slen, iter,
                            digest, keylen, out);
    Py_END_ALLOW_THREADS
#else
    if (strcmp(prf+5, "sha1"))
        RETURN_ERROR("unknown hash function in: %s", prf);

    MALLOC(out, keylen);
    Py_BEGIN_ALLOW_THREADS
    ret = PKCS5_PBKDF2_HMAC_SHA1(password, pwlen, salt, slen, iter,
                                 keylen, out);
    Py_END_ALLOW_THREADS
#endif

    CHECK_OPENSSL_ERROR(ret != 1);
    Presult = PyString_FromStringAndSize((char *) out, keylen);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    clear_free(out, keylen);
    return Presult;
}

/*
 * The openssl_random() funcion could have been implemented much easier in
 * Python using os.urandom() as the random source. We implement it in C below
 * because that we can be much more careful to wipe all intermediary data used
 * in the construction of the random string.
 */

static PyObject *
openssl_random(PyObject *self, PyObject *args)
{
    int i, count, nitems, size, ret, buflen, buf2len, seplen, offset;
    char *buf = NULL, *buf2 = NULL, *ptr, *sepptr;
    PyObject *alphabet = NULL, *separator = NULL, *item, *Presult = NULL;

    if (!PyArg_ParseTuple(args, "i|OO:random", &count, &alphabet, &separator))
        return NULL;

    if (alphabet == Py_None) {
        buflen = count;
        MALLOC(buf, buflen);
        ret = RAND_bytes((unsigned char *) buf, count);
        Presult = PyString_FromStringAndSize(buf, count);
        CHECK_PYTHON_ERROR(Presult == NULL);
    } else if (PyString_Check(alphabet)) {
        buflen = count;
        MALLOC(buf, buflen);
        buf2len = sizeof(unsigned int);
        MALLOC(buf2, buf2len);
        ptr = PyString_AS_STRING(alphabet);
        nitems = (int) PyString_GET_SIZE(alphabet);
        for (i=0; i<count; i++) {
            ret = RAND_bytes((unsigned char *) buf2, buf2len);
            CHECK_OPENSSL_ERROR(ret != 1);
            buf[i] = ptr[*((unsigned int *) buf2) % nitems];
        }
        Presult = PyString_FromStringAndSize(buf, buflen);
        CHECK_PYTHON_ERROR(Presult == NULL);
    } else if (PyUnicode_Check(alphabet)) {
        buflen = count * (int) sizeof(Py_UNICODE);
        MALLOC(buf, buflen);
        buf2len = sizeof (unsigned int);
        MALLOC(buf2, buf2len);
        ptr = (char *) PyUnicode_AS_UNICODE(alphabet);
        nitems = (int) PyUnicode_GET_SIZE(alphabet);
        for (i=0; i<count; i++) {
            ret = RAND_bytes((unsigned char *) buf2, buf2len);
            CHECK_OPENSSL_ERROR(ret != 1);
            ((Py_UNICODE *) buf)[i] =
                    ((Py_UNICODE *) ptr)[*((unsigned int *) buf2) % nitems];
        }
        Presult = PyUnicode_FromUnicode((Py_UNICODE *) buf, count);
        CHECK_PYTHON_ERROR(Presult == NULL);
    } else if (PySequence_Check(alphabet) && PySequence_Size(alphabet) > 0 &&
               PyString_Check(PySequence_GetItem(alphabet, 0))) {
        if (!(separator == NULL || separator == Py_None) &&
                    !PyString_Check(separator))
            RETURN_ERROR("separator must be string");
        buflen = count;
        MALLOC(buf, buflen);
        buf2len = sizeof (unsigned int);
        MALLOC(buf2, buf2len);
        nitems = (int) PySequence_Size(alphabet);
        if (separator == NULL || separator == Py_None) {
            seplen = 0;
            sepptr = NULL;
        } else { 
            seplen = (int) PyString_GET_SIZE(separator);
            sepptr = PyString_AS_STRING(separator);
        }
        for (i=0,offset=0; i<count; i++) {
            ret = RAND_bytes((unsigned char *) buf2, buf2len);
            CHECK_OPENSSL_ERROR(ret != 1);
            item = PySequence_GetItem(alphabet,
                        *((unsigned int *) buf2) % nitems);
            if (!PyString_Check(item))
                RETURN_ERROR("all items in the alphabet must be strings");
            ptr = PyString_AS_STRING(item);
            size = (int) PyString_GET_SIZE(item);
            while (offset + size + seplen > buflen)
                REALLOC(buf, buflen);
            memcpy(buf+offset, ptr, size);
            offset += size;
            if ((sepptr != NULL) && (i != count-1)) {
                memcpy(buf+offset, sepptr, seplen);
                offset += seplen;
            }
        }
        Presult = PyString_FromStringAndSize(buf, offset);
        CHECK_PYTHON_ERROR(Presult == NULL);
    } else if (PySequence_Check(alphabet) && PySequence_Size(alphabet) > 0 &&
               PyUnicode_Check(PySequence_GetItem(alphabet, 0))) {
        if (!(separator == NULL || separator == Py_None) &&
                    !PyUnicode_Check(separator))
            RETURN_ERROR("separator must be unicode");
        buflen = count * (int) sizeof (Py_UNICODE);
        MALLOC(buf, buflen);
        buf2len = sizeof (unsigned int);
        MALLOC(buf2, buf2len);
        nitems = (int) PySequence_Size(alphabet);
        if (separator == NULL || separator == Py_None) {
            seplen = 0;
            sepptr = NULL;
        } else { 
            seplen = (int) PyUnicode_GET_DATA_SIZE(separator);
            sepptr = (char *) PyUnicode_AS_UNICODE(separator);
        }
        for (i=0,offset=0; i<count; i++) {
            ret = RAND_bytes((unsigned char *) buf2, buf2len);
            CHECK_OPENSSL_ERROR(ret != 1);
            item = PySequence_GetItem(alphabet, *((unsigned int *) buf2) % nitems);
            if (!PyUnicode_Check(item))
                RETURN_ERROR("all items in the alphabet must be unicode");
            ptr = (char *) PyUnicode_AS_UNICODE(item);
            size = (int) PyUnicode_GET_DATA_SIZE(item);
            while (offset + size + seplen > buflen)
                REALLOC(buf, buflen);
            memcpy(buf+offset, ptr, size);
            offset += size;
            if ((sepptr != NULL) && (i != count-1)) {
                memcpy(buf+offset, sepptr, seplen);
                offset += seplen;
            }
        }
        Presult = PyUnicode_FromUnicode((Py_UNICODE *) buf,
                                        offset / sizeof (Py_UNICODE));
        CHECK_PYTHON_ERROR(Presult == NULL);
    } else
        RETURN_ERROR("'alphabet' must be a string, unicode, sequence of "
                     "string, sequence of unicode, or None");

error:
    clear_free(buf, buflen);
    clear_free(buf2, buf2len);
    return Presult;
}

#ifdef TEST_BUILD
/* The following few methods are infrastructure to test RSA-OAEP and RSA-PSS.
 * Both use random padding and so in order to use standard test vectors we
 * need to be able to set the random seed. */

static int (*_openssl_old_get_rand_bytes)(unsigned char *, int) = NULL;
static int _openssl_unrandom_bytes_len = 0;
static int _openssl_unrandom_bytes_idx = 0;
static char * _openssl_unrandom_bytes = NULL;

static int
_openssl_get_unrandom_bytes(unsigned char *buf, int num)
{
    int bytesleft, nbytes, ok = 0;

    ASSERT(_openssl_unrandom_bytes != NULL);
    ASSERT(_openssl_old_get_rand_bytes != NULL);

    bytesleft = _openssl_unrandom_bytes_len - _openssl_unrandom_bytes_idx;
    nbytes = (bytesleft < num) ? bytesleft : num;
    memcpy(buf, _openssl_unrandom_bytes, nbytes);
    _openssl_unrandom_bytes_idx += nbytes;

    if (num > nbytes)
        return _openssl_old_get_rand_bytes(buf+nbytes, num-nbytes);
    ok = 1;

error:
    return ok;
}

static PyObject *
_openssl_insert_random_bytes(PyObject *self, PyObject *args)
{
    char *buf;
    int buflen;
    RAND_METHOD *meth;
    PyObject *Pret = NULL;

    if (!PyArg_ParseTuple(args, "s#:_insert_random_bytes", &buf, &buflen))
        return NULL;

    if (_openssl_unrandom_bytes != NULL)
    {
        ASSERT(_openssl_unrandom_bytes_len > 0);
        ASSERT(_openssl_old_get_rand_bytes != NULL);
        free(_openssl_unrandom_bytes);
    }
    MALLOC(_openssl_unrandom_bytes, buflen);
    memcpy(_openssl_unrandom_bytes, buf, buflen);
    _openssl_unrandom_bytes_len = buflen;
    _openssl_unrandom_bytes_idx = 0;

    if (_openssl_old_get_rand_bytes == NULL)
    {
        meth = (RAND_METHOD *) RAND_get_rand_method();
        ASSERT(meth != NULL);
        _openssl_old_get_rand_bytes = meth->bytes;
        meth->bytes = _openssl_get_unrandom_bytes;
    }

    Py_INCREF(Py_None);
    Pret = Py_None;

error:
    return Pret;
}
#endif  /* TEST_BUILD */


static PyMethodDef openssl_methods[] =
{
    { "rsa_genkey", (PyCFunction) openssl_rsa_genkey, METH_VARARGS },
    { "rsa_checkkey", (PyCFunction) openssl_rsa_checkkey, METH_VARARGS },
    { "rsa_size", (PyCFunction) openssl_rsa_size, METH_VARARGS },
    { "rsa_encrypt", (PyCFunction) openssl_rsa_encrypt, METH_VARARGS },
    { "rsa_decrypt", (PyCFunction) openssl_rsa_decrypt, METH_VARARGS },
    { "rsa_sign", (PyCFunction) openssl_rsa_sign, METH_VARARGS },
    { "rsa_verify", (PyCFunction) openssl_rsa_verify, METH_VARARGS },
    { "dh_genparams", (PyCFunction) openssl_dh_genparams, METH_VARARGS },
    { "dh_checkparams", (PyCFunction) openssl_dh_checkparams, METH_VARARGS },
    { "dh_size", (PyCFunction) openssl_dh_size, METH_VARARGS },
    { "dh_genkey", (PyCFunction) openssl_dh_genkey, METH_VARARGS },
    { "dh_checkkey", (PyCFunction) openssl_dh_checkkey, METH_VARARGS },
    { "dh_compute", (PyCFunction) openssl_dh_compute, METH_VARARGS },
    { "aes_encrypt", (PyCFunction) openssl_aes_encrypt, METH_VARARGS },
    { "aes_decrypt", (PyCFunction) openssl_aes_decrypt, METH_VARARGS },
    { "pbkdf2", (PyCFunction) openssl_pbkdf2, METH_VARARGS },
    { "random", (PyCFunction) openssl_random, METH_VARARGS },
#ifdef TEST_BUILD
    { "_insert_random_bytes",
        (PyCFunction) _openssl_insert_random_bytes, METH_VARARGS },
#endif
    { NULL, NULL }
};


void initopenssl(void)
{
    PyObject *Pmodule, *Pdict;

    /* Import _ssl from the standard library so that it will initialize
     * the OpenSSL library for us. */
    if (!PyImport_ImportModule("_ssl"))
        return;
    if ((Pmodule = Py_InitModule("openssl", openssl_methods)) == NULL)
        return;
    if ((Pdict = PyModule_GetDict(Pmodule)) == NULL)
        return;
    if ((openssl_Error = PyErr_NewException("openssl.Error", NULL, NULL)) == NULL)
        return;
    if (PyDict_SetItemString(Pdict, "Error", openssl_Error) == -1)
        return;
}
