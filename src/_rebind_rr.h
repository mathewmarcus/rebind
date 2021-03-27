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
    size_t subdomain_len;
};

struct rr *new_rr(char *name, const char *target, const int ai_family);
struct rr *find_rr(char *query_name, const size_t query_name_len, size_t base_name_len, struct rr *root);
int load_resource_records(const char *filename, const int ai_family, struct rr *rr_list);
#endif