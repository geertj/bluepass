/*
 * This file is part of MPM. MPM is Copyright (c) 2012 by Geert Jansen. All
 * rights are reserved.
 *
 * This is a Python C extension module that adds a few extra functions for
 * to the Python _ssl module.
 */

#include <Python.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/err.h>
#include <openssl/dh.h>


static PyObject *sslex_Error = NULL;


#define RETURN_ERROR(fmt, ...) \
    do { \
        if ((fmt) != NULL) PyErr_Format(sslex_Error, fmt, ## __VA_ARGS__); \
        goto error; \
    } while (0)

#define CHECK_ERROR(cond, fmt, ...) \
    do { if (cond) { RETURN_ERROR(fmt, ## __VA_ARGS__); } } while (0)

#define CHECK_OPENSSL_ERROR(cond) \
    CHECK_ERROR(cond, ERR_error_string(ERR_get_error(), NULL))


/* 
 * Define a shadow structure that has the same layout as PySSLObject from
 * the _ssl module. This allows us to compile this module separately from
 * the Python source tree. Fortunately, the format has been kept consistent
 * in Python 2.6 and 2.7 (our target). If we wanted to port this module to
 * Python 3.x then this needs to be updated as the "ctx" member has been
 * removed.
 */

typedef struct
{
    PyObject_HEAD
    PyObject *Socket;
    SSL_CTX *ctx;
    SSL *ssl;
} PySSLShadowObject;


static PyObject *
sslex_set_ciphers(PyObject *self, PyObject *args)
{
    char *ciphers;
    PyObject *Pret = NULL;
    PySSLShadowObject *sslob;

    if (!PyArg_ParseTuple(args, "Os:set_ciphers", &sslob, &ciphers))
        return NULL;
    if (strcmp(sslob->ob_type->tp_name, "ssl.SSLContext"))
        RETURN_ERROR("expecting a SSLContext");
    if (!SSL_set_cipher_list(sslob->ssl, ciphers))
        RETURN_ERROR("SSL_set_cipher_list() failed");

    Py_INCREF(Py_None);
    Pret = Py_None;

error:
    return Pret;
}

 
static PyObject *
sslex_get_channel_binding(PyObject *self, PyObject *args)
{
    PyObject *Pcb = NULL;
    PySSLShadowObject *sslob;

    if (!PyArg_ParseTuple(args, "O:get_channel_binding", &sslob))
        return NULL;
    if (strcmp(sslob->ob_type->tp_name, "ssl.SSLContext"))
        RETURN_ERROR("expecting a SSLContext");
    if (sslob->ssl->s3 == NULL)
        RETURN_ERROR("cannot get channel binding for SSLv2");

    if (SSL_session_reused(sslob->ssl) ^ !sslob->ssl->server)
        Pcb = PyString_FromStringAndSize((char *) sslob->ssl->s3->tmp.finish_md,
                    sslob->ssl->s3->tmp.finish_md_len);
    else
        Pcb = PyString_FromStringAndSize((char *) sslob->ssl->s3->tmp.peer_finish_md,
                    sslob->ssl->s3->tmp.peer_finish_md_len);

error:
    return Pcb;
}

static PyObject *
sslex_set_dh_params(PyObject *self, PyObject *args)
{
    unsigned char *params;
    int paramslen, single_use, ret;
    PyObject *Pret = NULL;
    PySSLShadowObject *sslob;
    DH *dh = NULL;

    if (!PyArg_ParseTuple(args, "Os#i:set_dh_params", &sslob, &params,
                          &paramslen, &single_use))
        return NULL;
    if (strcmp(sslob->ob_type->tp_name, "ssl.SSLContext"))
        RETURN_ERROR("expecting a SSLContext");

    dh = d2i_DHparams(NULL, (const unsigned char **) &params, paramslen);
    CHECK_OPENSSL_ERROR(dh == NULL);
    ret = SSL_set_tmp_dh(sslob->ssl, dh);
    CHECK_OPENSSL_ERROR(ret != 1);
    
    if (single_use)
        SSL_set_options(sslob->ssl, SSL_OP_SINGLE_DH_USE);

    Py_INCREF(Py_None);
    Pret = Py_None;

error:
    DH_free(dh);
    return Pret;
}

static PyObject *
sslex__set_accept_state(PyObject *self, PyObject *args)
{
    PyObject *Pret = NULL;
    PySSLShadowObject *sslob;

    if (!PyArg_ParseTuple(args, "O:_set_accept_state", &sslob))
        return NULL;
    if (strcmp(sslob->ob_type->tp_name, "ssl.SSLContext"))
        RETURN_ERROR("expecting a SSLContext");

    SSL_set_accept_state(sslob->ssl);

    Py_INCREF(Py_None);
    Pret = Py_None;

error:
    return Pret;
}

static PyMethodDef sslex_methods[] =
{
    { "set_ciphers",
            (PyCFunction) sslex_set_ciphers, METH_VARARGS },
    { "get_channel_binding",
            (PyCFunction) sslex_get_channel_binding, METH_VARARGS },
    { "set_dh_params",
            (PyCFunction) sslex_set_dh_params, METH_VARARGS },
    { "_set_accept_state",
            (PyCFunction) sslex__set_accept_state, METH_VARARGS },
    { NULL, NULL }
};


void init_sslex(void)
{
    PyObject *Pmodule, *Pdict;

    /* Assume _ssl has done these:
    SSL_load_error_strings();
    SSL_library_init();
     */

    if ((Pmodule = Py_InitModule("_sslex", sslex_methods)) == NULL)
        return;
    if ((Pdict = PyModule_GetDict(Pmodule)) == NULL)
        return;
    if ((sslex_Error = PyErr_NewException("_sslex.Error", NULL, NULL)) == NULL)
        return;
    if (PyDict_SetItemString(Pdict, "Error", sslex_Error) == -1)
        return;
}
