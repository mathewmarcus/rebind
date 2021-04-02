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
    int sent_num_valid;
    struct rr *next;
    size_t subdomain_len;
    uint32_t ttl;
};

extern int should_reload;

void free_rr_list(struct rr *root);
struct rr *new_rr(char *name, const char *target, const uint32_t ttl, const int ai_family);
struct rr *find_rr(const char *query_name, const size_t query_name_len, const size_t base_name_len, struct rr *root);
struct rr *find_subdomain_rr(const char *name, const size_t len, struct rr *root);
int load_resource_records(const char *filename, const int ai_family, char *domain, const char *host_ip, uint32_t ttl, struct rr **rr_list);
int reload_resource_records(const char *filename, const int ai_family, char *domain, const char *host_ip, uint32_t ttl, struct rr **rr_list);
void set_reload_flag(int signal);
#endif