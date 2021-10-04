// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pysnoop.h"

const volatile pid_t targ_tgid = 0;

typedef long int		intptr_t;
typedef intptr_t        Py_intptr_t;
typedef Py_intptr_t     Py_ssize_t;
typedef Py_ssize_t Py_hash_t;
#define _PyObject_HEAD_EXTRA            \
    void *_ob_next;           \
    void *_ob_prev;

typedef struct _object {
    _PyObject_HEAD_EXTRA
    Py_ssize_t ob_refcnt;
    void *ob_type;
} PyObject;

typedef struct {
    PyObject ob_base;
    Py_ssize_t ob_size; /* Number of items in variable part */
} PyVarObject;

#define PyObject_VAR_HEAD      PyVarObject ob_base;
typedef struct {
    PyObject_VAR_HEAD
    Py_hash_t ob_shash;
    char ob_sval[1];
    /* Invariants:
     *     ob_sval contains space for 'ob_size+1' elements.
     *     ob_sval[ob_size] == 0.
     *     ob_shash is the hash of the byte string or -1 if not computed yet.
     */
} PyBytesObject;

/*
PyAPI_FUNC(int) PySys_Audit(
    const char *event,
    const char *argFormat,
    ...);
*/
SEC("uprobe/pysys_audit")
int BPF_KPROBE(pysys_audit, const char *u_event, const char *u_arg_format, char *u_code, PyBytesObject* u_filename)
{
    u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;

	if (targ_tgid && targ_tgid != tgid)
		return 0;

    // Only look at 'compile' events
    const char* compile = "compile";
    char event[20];
    bpf_probe_read_user(&event, sizeof(event), u_event);
    event[sizeof(event)-1] = '\x00';
    // bpf_printk("pid %d | event %s", tgid, event);
    for (int i = 0; i < sizeof(compile); i++) {
        if (compile[i] != event[i]) {
            return 0;
        }
    }

    // For now only check this arg format
    char arg_format[10];
    bpf_probe_read_user(&arg_format, sizeof(arg_format), u_arg_format);
    arg_format[sizeof(arg_format)-1] = '\x00';
    if (arg_format[0] == 'y') {
        char code[100];
        bpf_probe_read_user(&code, sizeof(code), u_code);
        code[sizeof(code)-1] = '\x00';

        char fname[100];
        bpf_probe_read_user(&fname, sizeof(fname), (char*)u_filename->ob_sval);
        fname[sizeof(fname)-1] = '\x00';

        // bpf_printk("pid %d | code '%s' | fname '%s'", tgid, code, fname);
        return 0;
    }
    else if (arg_format[0] == 'O') {
        char fname[100];
        bpf_probe_read_user(&fname, sizeof(fname), (char*)u_filename->ob_sval);
        fname[sizeof(fname)-1] = '\x00';

    
        char fname[100];
        bpf_probe_read_user(&fname, sizeof(fname), (char*)u_filename->ob_sval);
        fname[sizeof(fname)-1] = '\x00';
        bpf_printk("pid %d | fname '%s'", tgid, fname);
        return 0;
    }


	return 0;
}

char LICENSE[] SEC("license") = "GPL";
