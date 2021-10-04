// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC.
 *
 * Based on pysnoop from BCC by Brendan Gregg and others
 * 2021-02-26   Barret Rhoden   Created this.
 *
 * TODO:
 * - support uprobes on libraries without -p PID. (parse ld.so.cache)
 * - support regexp pattern matching and per-function histograms
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pysnoop.h"
#include "pysnoop.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	pid_t pid;
    char libpython_path[PATH_MAX];
} env = {
	.pid = 0,
    .libpython_path = "/usr/lib64/libpython3.9.so",
};

const char *argp_program_version = "pysnoop 1.0";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
"\n"
;

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace"},
	{ "library", 'l', "libpython", 0, "full alternate path to libpython"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;
	long pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env->pid = pid;
		break;
	case 'l':
        if (strlen(arg) >= PATH_MAX) {
			warn("Library path too long: %s\n", arg);
			argp_usage(state);
        }
        strncpy(env->libpython_path, arg, sizeof(env->libpython_path)-1);
        break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int attach_uprobes(struct pysnoop_bpf *obj)
{
    int ret = -1;
	char bin_path[PATH_MAX];
	off_t func_off;
	long err;

    strcpy(bin_path, env.libpython_path);

    func_off = get_elf_func_offset(bin_path, "PySys_Audit");
	if (func_off < 0) {
		warn("Could not find PySys_Audit in %s\n", env.libpython_path);
		return ret;
	}

    obj->links.pysys_audit =
		bpf_program__attach_uprobe(obj->progs.pysys_audit, false,
					   env.pid ?: -1, bin_path, func_off);
	err = libbpf_get_error(obj->links.pysys_audit);
	if (err) {
		warn("Failed to attach uprobe: %ld\n", err);
		return ret;
	}
    
	ret = 0;

	return ret;
}

static volatile bool exiting;
static void sig_hand(int signr)
{
	exiting = true;
}
static struct sigaction sigact = {.sa_handler = sig_hand};

static void read_trace_pipe(void) {
    int trace_fd;

    trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd == -1) {
        printf("Error opening trace_pipe: %s\n", strerror(errno));
        return;
    }

    while (!exiting) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) -1);
        if (sz > 0) {
            buf[sz] = '\x00';
            puts(buf);
        }
    }
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = program_doc,
	};
	struct pysnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	sigaction(SIGINT, &sigact, 0);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = pysnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_tgid = env.pid;

	err = pysnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		return 1;
	}

	err = attach_uprobes(obj);
	if (err)
		goto cleanup;

    printf("Successfully started!\n");
    read_trace_pipe();
	printf("Exiting trace\n");

cleanup:
	pysnoop_bpf__destroy(obj);

	return err != 0;
}
