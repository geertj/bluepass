/*
 * This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
 * Geert Jansen.
 *
 * Bluepass is free software available under the GNU General Public License,
 * version 3. See the file LICENSE distributed with this file for the exact
 * licensing terms.
 */

#include <Python.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>


static PyObject *secmem_Error = NULL;

#define RETURN_ERROR(fmt, ...) \
    do { \
        if ((fmt) != NULL) PyErr_Format(secmem_Error, fmt, ## __VA_ARGS__); \
        goto error; \
    } while (0)


#if defined(__linux__) || defined(__APPLE__)

static PyObject *
secmem_lock(PyObject *self, PyObject *args)
{
    char *start, *end;
    int ret;
    long pagesize;
    PyStringObject *s;
    PyObject *Pret = NULL;

    if (!PyArg_ParseTuple(args, "O!:lock", &PyString_Type, &s))
        return NULL;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0)
        RETURN_ERROR("sysconf(): %s", strerror(errno));

    start = (char *) s;
    start -= ((unsigned long) start % pagesize);
    end = (char *) s + s->ob_size - 1;
    end += (pagesize - (unsigned long) end % pagesize);
    ret = mlock(start, end-start);
    Pret = PyInt_FromLong(!(ret < 0));

error:
    return Pret;
}

static PyObject *
secmem_unlock(PyObject *self, PyObject *args)
{
    char *start, *end;
    int ret;
    long pagesize;
    PyStringObject *s;
    PyObject *Pret = NULL;

    if (!PyArg_ParseTuple(args, "O!:unlock", &PyString_Type, &s))
        return NULL;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0)
        RETURN_ERROR("sysconf(): %s", strerror(errno));

    start = (char *) s;
    start -= ((unsigned long) start % pagesize);
    end = (char *) s + s->ob_size - 1;
    end += (pagesize - (unsigned long) end % pagesize);
    ret = munlock(start, end-start);
    Pret = PyInt_FromLong(!(ret < 0));

error:
    return Pret;
}

#else

static PyObject *
secmem_lock(PyObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, "O!:lock", &PyString_Type, &s))
        return NULL;
    return PyInt_FromLong(0);
}

static PyObject *
secmem_unlock(PyObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, "O!:lock", &PyString_Type, &s))
        return NULL;
    return PyInt_FromLong(0);
}

#endif

static PyObject *
secmem_wipe(PyObject *self, PyObject *args)
{
    PyObject *obj, *Pret = NULL;
    PyStringObject *s;
    PyUnicodeObject *u;

    if (!PyArg_ParseTuple(args, "O", &obj))
        return NULL;

    if (PyString_Check(obj)) {
        s = (PyStringObject *) obj;
        memset(s->ob_sval, 0, s->ob_size);
        s->ob_shash = -1;
    } else if (PyUnicode_Check(obj)) {
        u = (PyUnicodeObject *) obj;
        memset(u->str, 0, u->length);
        u->hash = -1;
    } else
        RETURN_ERROR("expecting str or unicode object");

    Py_INCREF(Py_None);
    Pret = Py_None;

error:
    return Pret;
}

#if defined(__linux__)

#include <sys/prctl.h>

static PyObject *
secmem_disable_ptrace(PyObject *self, PyObject *args)
{
    int ret;
    PyObject *Pret;

    if (!PyArg_ParseTuple(args, ":disable_ptrace"))
        return NULL;
    ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    Pret = PyBool_FromLong(!(ret < 0));
    return Pret;
}

#else

static PyObject *
secmem_disable_ptrace(PyObject *self, PyObject *args)
{
    PyObject *Pret;

    if (!PyArg_ParseTuple(args, ":disable_ptrace"))
        return NULL;
    PyErr_WarnEx(PyExc_UserWarning, "don't know how to disable ptrace() "
                 "on this platform", 1);
    Pret = PyBool_FromLong(0);
    return Pret;
}

#endif

static PyMethodDef secmem_methods[] =
{
    { "lock", (PyCFunction) secmem_lock, METH_VARARGS },
    { "unlock", (PyCFunction) secmem_unlock, METH_VARARGS },
    { "wipe", (PyCFunction) secmem_wipe, METH_VARARGS },
    { "disable_ptrace", (PyCFunction) secmem_disable_ptrace, METH_VARARGS },
    { NULL, NULL }
};

void
initsecmem(void)
{
    PyObject *Pdict, *Pmodule;

    if ((Pmodule = Py_InitModule("secmem", secmem_methods)) == NULL)
        return;
    if ((Pdict = PyModule_GetDict(Pmodule)) == NULL)
        return;
    if ((secmem_Error = PyErr_NewException("secmem.Error", NULL, NULL)) == NULL)
        return;
    if (PyDict_SetItemString(Pdict, "Error", secmem_Error) == -1)
        return;
}
