// -----------------------------------------------------------------------
// Python bindings for bluepoint2.

#include <Python.h>
#include <pygobject.h>

#include "rsamod.h"
#include "../bluepoint2.h"
#include "bdate.h"

#define OPEN_IMAGE 1

// -----------------------------------------------------------------------
// Vars:

PyObject *module;                   // This is us

static  char version[] = "1.0";

static PyObject *_bdate(PyObject *self, PyObject *args, PyObject *kwargs)
{
  return Py_BuildValue("s", bdate);
}

static PyObject *_version(PyObject *self, PyObject *args, PyObject *kwargs)
{
    return Py_BuildValue("s", version);
}


static PyObject *_encrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "buffer", "password",  NULL };
    char *buff = "";  char *passw = ""; char *mem;
    int  blen = 0, plen = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#s#", kwlist,
                    &buff, &blen, &passw, &plen))
        return NULL;
    mem = malloc(blen+1);
    if(mem == NULL)
        {
        return PyErr_NoMemory();
        }
    memcpy(mem, buff, blen);
    bluepoint2_encrypt(mem, blen, passw, plen);
    mem[blen] = 0;
    return Py_BuildValue("s#", mem, blen);
}

static PyObject *_decrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "buffer", "password",  NULL };
    char *buff = ""; char *passw = ""; char *mem;
    int  blen = 0, plen = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#s#", kwlist,
                    &buff, &blen, &passw, &plen))
        return NULL;
    mem = malloc(blen + 1);
    if(mem == NULL)
        {
        return PyErr_NoMemory();
        }
    memcpy(mem, buff, blen);
    bluepoint2_decrypt(mem, blen, passw, plen);
    mem[blen] = 0;
    return Py_BuildValue("s#", mem, blen);
}

static PyObject *_tohex(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "buffer", NULL };
    char *buff = ""; char *mem;
    int  blen = 0, plen = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#", kwlist,
                        &buff, &blen))
        return NULL;
    plen = 3*blen;
    mem = malloc(plen);
    if(mem == NULL)
        {
        return PyErr_NoMemory();
        }
    bluepoint2_tohex(buff, blen, mem, &plen);
    return Py_BuildValue("s#", mem, plen);
}

// Erase object. If null specified, encrypt it

static PyObject *_destroy(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "buffer",  "fill", NULL };
    char *buff = ""; int  blen = 0; int fill = '0';

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#|i", kwlist,
                        &buff, &blen, &fill))
        return NULL;
    memset(buff, fill, blen);
    if(fill == 0)
        bluepoint2_encrypt(buff, blen, "bluepoint2", 10);

    return Py_BuildValue("i", 0);
}

static PyObject *_fromhex(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = { "buffer",  NULL };
    char *buff = ""; char *mem;
    int  blen = 0, plen = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#", kwlist,
                        &buff, &blen))
        return NULL;
    plen = 3*blen;
    mem = malloc(plen);
    if(mem == NULL)
        {
        return PyErr_NoMemory();
        }
    bluepoint2_fromhex(buff, blen, mem, &plen);
    return Py_BuildValue("s#", mem, plen);
}

// Define module

PyMethodDef rsamod_functions[] =
    {

    { "version",   (PyCFunction)_version, METH_VARARGS|METH_KEYWORDS, "rsamod version."},
    { "builddate", (PyCFunction)_bdate,   METH_VARARGS|METH_KEYWORDS, "rsamod build date."},
    { "encrypt",   (PyCFunction)_encrypt, METH_VARARGS|METH_KEYWORDS, \
        "rsamod encryption. Pass buffer and pass."},
    { "decrypt",   (PyCFunction)_decrypt, METH_VARARGS|METH_KEYWORDS, \
        "rsamod decryption. Pass buffer and pass."},
    { "destroy",   (PyCFunction)_destroy, METH_VARARGS|METH_KEYWORDS,
        "rsamod destruction. Scramble variable. Fill with '0' or number. " \
        "Pass zero to randomize."},
    { "tohex",     (PyCFunction)_tohex,   METH_VARARGS|METH_KEYWORDS, \
        "rsamod tohex. Convert to hex string."},
    { "fromhex",   (PyCFunction)_fromhex, METH_VARARGS|METH_KEYWORDS, \
        "rsamod fromhex. Convert from hex string."},

    {  NULL },
    };

// -----------------------------------------------------------------------
// Init:

DL_EXPORT(void)
initrsamod(void)
{
    init_pygobject ();

    module = Py_InitModule3("rsamod", rsamod_functions, "Bluepoint encryption library for Python.");
    //d = PyModule_GetDict (module);

    // Constants
    PyModule_AddIntConstant(module, (char *)"OPEN", 1);
    PyModule_AddStringConstant(module, (char *)"author", "Peter Glen");

    // Values:
    PyModule_AddObject(module, "verbose",   Py_BuildValue("i", 0));

    if (PyErr_Occurred ()) {
	   Py_FatalError ("can't initialise rsamod module");
    }
}




















