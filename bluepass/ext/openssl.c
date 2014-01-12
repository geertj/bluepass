/*
 * This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
 * Geert Jansen.
 *
 * Bluepass is free software available under the GNU General Public License,
 * version 3. See the file LICENSE distributed with this file for the exact
 * licensing terms.
 */

#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/evp.h>


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

#define PyBytes_ClearFree(s) \
    do { if (s != NULL) { \
        PyBytesObject *_s = (PyBytesObject *) s; \
        if (_s->ob_sval && Py_SIZE(_s) > 0) \
            memset(_s->ob_sval, 0, Py_SIZE(_s)); \
        Py_DECREF(s); \
    } } while (0)


#if PY_MAJOR_VERSION >= 3
#  define MOD_OK(val) (val)
#  define MOD_ERROR NULL
#  define MOD_INITFUNC(name) PyMODINIT_FUNC PyInit_ ## name(void)
#  define INIT_MODULE(mod, name, doc, methods) \
        do { \
            static struct PyModuleDef moduledef = { \
                PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
            mod = PyModule_Create(&moduledef); \
        } while (0)
#  define BS "y#"
#else
#  define MOD_OK(value)
#  define MOD_ERROR
#  define MOD_INITFUNC(name) void init ## name(void)
#  define INIT_MODULE(mod, name, doc, methods) \
          do { mod = Py_InitModule3(name, methods, doc); } while (0)
#  define BS "s#"
#endif


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
    Pprivkey = PyBytes_FromStringAndSize((char *) privkey, privlen);
    CHECK_PYTHON_ERROR(Pprivkey == NULL);
    Ppubkey = PyBytes_FromStringAndSize((char *) pubkey, publen);
    CHECK_PYTHON_ERROR(Ppubkey == NULL);
    PyTuple_SET_ITEM(Presult, 0, Pprivkey);
    PyTuple_SET_ITEM(Presult, 1, Ppubkey);
    goto cleanup;

error:
    Py_XDECREF(Presult);
    PyBytes_ClearFree(Pprivkey);
    PyBytes_ClearFree(Ppubkey);

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

    if (!PyArg_ParseTuple(args, BS ":rsa_size", &key, &keylen))
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

    if (!PyArg_ParseTuple(args, BS ":rsa_size", &key, &keylen))
        return NULL;

    rsa = d2i_RSAPublicKey(NULL, (const unsigned char **) &key, keylen);
    CHECK_OPENSSL_ERROR(rsa == NULL);
    Presult = PyLong_FromLong(RSA_size(rsa) * 8);
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

    if (!PyArg_ParseTuple(args, BS BS "s:rsa_encrypt", &in, &inlen,
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
    Pout = PyBytes_FromStringAndSize((char *) out, size);
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

    if (!PyArg_ParseTuple(args, BS BS "s:rsa_decrypt", &in, &inlen,
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
    Pout = PyBytes_FromStringAndSize((char *) out, size);
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

    if (!PyArg_ParseTuple(args, BS BS "s:rsa_sign", &in, &inlen,
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
    Psig = PyBytes_FromStringAndSize((char *) sig, size);
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

    if (!PyArg_ParseTuple(args,  BS BS BS "s:rsa_verify", &in, &inlen,
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
openssl_aes_encrypt(PyObject *self, PyObject *args)
{
    char *mode;
    unsigned char *in, *pad = NULL, *out = NULL, *iv, *iv2 = NULL, *ukey;
    int inlen, padlen, outlen, ukeylen, ivlen, i, ret;
    AES_KEY key;
    PyObject *Pout = NULL;

    if (!PyArg_ParseTuple(args, BS BS BS "s:aes_encrypt", &in, &inlen,
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
    Pout = PyBytes_FromStringAndSize((char *) out, outlen);
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

    if (!PyArg_ParseTuple(args, BS BS BS "s:aes_decrypt", &in, &inlen,
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
    Pout = PyBytes_FromStringAndSize((char *) out, inlen-padlen);
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
    Presult = PyBytes_FromStringAndSize((char *) out, keylen);
    CHECK_PYTHON_ERROR(Presult == NULL);

error:
    clear_free(out, keylen);
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

    if (!PyArg_ParseTuple(args, BS ":_insert_random_bytes", &buf, &buflen))
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
    { "aes_encrypt", (PyCFunction) openssl_aes_encrypt, METH_VARARGS },
    { "aes_decrypt", (PyCFunction) openssl_aes_decrypt, METH_VARARGS },
    { "pbkdf2", (PyCFunction) openssl_pbkdf2, METH_VARARGS },
#ifdef TEST_BUILD
    { "_insert_random_bytes",
        (PyCFunction) _openssl_insert_random_bytes, METH_VARARGS },
#endif
    { NULL, NULL }
};

PyDoc_STRVAR(openssl_doc, "wrapped OpenSSL methods");


MOD_INITFUNC(openssl)
{
    PyObject *Pmodule, *Pdict;

    /* Import _ssl from the standard library so that it will initialize
     * the OpenSSL library for us. */
    if (!PyImport_ImportModule("_ssl"))
        return MOD_ERROR;

    INIT_MODULE(Pmodule, "openssl", openssl_doc, openssl_methods);

    if ((Pdict = PyModule_GetDict(Pmodule)) == NULL)
        return MOD_ERROR;
    if ((openssl_Error = PyErr_NewException("openssl.Error", NULL, NULL)) == NULL)
        return MOD_ERROR;
    if (PyDict_SetItemString(Pdict, "Error", openssl_Error) == -1)
        return MOD_ERROR;

    return MOD_OK(Pmodule);
}
