#ifndef _REBIND_RR_H
#define _REBIND_RR_H

#include <stdlib.h>
#include <netinet/ip.h>


struct rr {
    char *name;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        char *name;
    } target;
    int use_restricted;
    struct rr *next;
};

int add_rr(struct rr *root, char *name, const char *target, const int ai_family);
ssize_t load_resource_records(const char *filename, const int ai_family, struct rr *rr_list);
#endif