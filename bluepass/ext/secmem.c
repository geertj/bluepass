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


static PyObject *secmem_Error = NULL;

#define RETURN_ERROR(fmt, ...) \
    do { \
        if ((fmt) != NULL) PyErr_Format(secmem_Error, fmt, ## __VA_ARGS__); \
        goto error; \
    } while (0)


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
#else
#  define MOD_OK(value)
#  define MOD_ERROR
#  define MOD_INITFUNC(name) void init ## name(void)
#  define INIT_MODULE(mod, name, doc, methods) \
          do { mod = Py_InitModule3(name, methods, doc); } while (0)
#endif


#if defined(__linux__) || defined(__APPLE__)

#include <sys/mman.h>

static PyObject *
secmem_lock(PyObject *self, PyObject *args)
{
    char *start, *end;
    int ret;
    long pagesize;
    PyBytesObject *b;
    PyObject *Pret = NULL;

    if (!PyArg_ParseTuple(args, "O!:lock", &PyBytes_Type, &b))
        return NULL;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0)
        RETURN_ERROR("sysconf(): %s", strerror(errno));

    start = (char *) b;
    start -= ((unsigned long) start % pagesize);
    end = (char *) b + Py_SIZE(b) - 1;
    end += (pagesize - (unsigned long) end % pagesize);
    ret = mlock(start, end-start);
    Pret = PyLong_FromLong(!(ret < 0));

error:
    return Pret;
}

static PyObject *
secmem_unlock(PyObject *self, PyObject *args)
{
    char *start, *end;
    int ret;
    long pagesize;
    PyBytesObject *b;
    PyObject *Pret = NULL;

    if (!PyArg_ParseTuple(args, "O!:unlock", &PyBytes_Type, &b))
        return NULL;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0)
        RETURN_ERROR("sysconf(): %s", strerror(errno));

    start = (char *) b;
    start -= ((unsigned long) start % pagesize);
    end = (char *) b + Py_SIZE(b) - 1;
    end += (pagesize - (unsigned long) end % pagesize);
    ret = munlock(start, end-start);
    Pret = PyLong_FromLong(!(ret < 0));

error:
    return Pret;
}

#else

static PyObject *
secmem_lock(PyObject *self, PyObject *args)
{
    PyBytesObject *b;

    if (!PyArg_ParseTuple(args, "O!:lock", &PyBytes_Type, &b))
        return NULL;

    PyErr_WarnEx(PyExc_UserWarning, "mlock() is not available", 1);

    return PyInt_FromLong(0);
}

static PyObject *
secmem_unlock(PyObject *self, PyObject *args)
{
    PyBytesObject *b;

    if (!PyArg_ParseTuple(args, "O!:lock", &PyBytes_Type, &b))
        return NULL;

    PyErr_WarnEx(PyExc_UserWarning, "munlock() is not available", 1);

    return PyInt_FromLong(0);
}

#endif

static PyObject *
secmem_wipe(PyObject *self, PyObject *args)
{
    PyObject *Pret = NULL;
    PyBytesObject *b;

    if (!PyArg_ParseTuple(args, "O!", &PyBytes_Type, &b))
        return NULL;

    memset(b->ob_sval, 0, Py_SIZE(b));
    b->ob_shash = -1;

    Py_INCREF(Py_None);
    Pret = Py_None;

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

    PyErr_WarnEx(PyExc_UserWarning, "prctl() is not available", 1);
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

PyDoc_STRVAR(secmem_doc, "Secure memory functions");

MOD_INITFUNC(secmem)
{
    PyObject *Pdict, *Pmodule;

    INIT_MODULE(Pmodule, "secmem", secmem_doc, secmem_methods);

    if ((Pdict = PyModule_GetDict(Pmodule)) == NULL)
        return MOD_ERROR;
    if ((secmem_Error = PyErr_NewException("secmem.Error", NULL, NULL)) == NULL)
        return MOD_ERROR;
    if (PyDict_SetItemString(Pdict, "Error", secmem_Error) == -1)
        return MOD_ERROR;

    return MOD_OK(Pmodule);
}
