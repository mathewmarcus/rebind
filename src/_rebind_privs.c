#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "_rebind_privs.h"

#ifdef CAP_FOUND
#include <sys/capability.h>
#endif


int raise_privs() {
    #ifdef CAP_FOUND
    cap_t caps;
    cap_value_t cap_list[1] = { CAP_NET_BIND_SERVICE };
    cap_flag_value_t privileged;

    if (!(caps = cap_get_proc())) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for process capabilities\", \"error\": \"%s\"}\n", strerror(errno));
        return -1;
    }

    /*
        No need to raise capailities in either of the following cases:
            * file effective bit is already sit (e.g. setcap "cap_net_bind_service=ep")
            * file is setuid root (all permitted, inheritable, and effective capabilities bits will already be set)
    */
    if (cap_get_flag(caps, cap_list[0], CAP_EFFECTIVE, &privileged)) {
        fprintf(stderr, "{\"message\": \"Failed to check if CAP_NET_BIND_SERVICE is effective\", \"error\": \"%s\"}\n", strerror(errno));
        cap_free(caps);
        return -1;
    }

    if (privileged == CAP_CLEAR) {
        if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
            fprintf(stderr, "{\"message\": \"Failed to set cap flag\", \"error\": \"%s\"}\n", strerror(errno));
            cap_free(caps);
            return -1;
        }

        if (cap_set_proc(caps) == -1) {
            fprintf(stderr, "{\"message\": \"Failed to enable CAP_NET_BIND_SERVICE\", \"error\": \"%s\"}\n", strerror(errno));
            cap_free(caps);
            return -1;
        }
    }
    cap_free(caps);
    #endif

    return 0;
}


int drop_privs() {
    cap_t caps;

    #ifdef CAP_FOUND
    if (!(caps = cap_init())) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for process capabilities\", \"error\": \"%s\"}\n", strerror(errno));
        return -1;
    }

    if (cap_set_proc(caps) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to drop process capabilities\", \"error\": \"%s\"}\n", strerror(errno));
        cap_free(caps);
        return -1;
    }
    cap_free(caps);
    #endif


    if (setuid(getuid()) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to permanently drop privileges\", \"error\": \"%s\"}\n", strerror(errno));
        return -1;
    }
}