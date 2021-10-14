#ifndef _REBIND_RR_H
#define _REBIND_RR_H

#include <stdlib.h>
#include <netinet/ip.h>

#define MAX_NAME_LEN 255

enum query_type {
    A = 0x0001,
    NS = 0x0002,
    CNAME = 0x0005,
    AAAA = 0x001C
};

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
    enum query_type qtype;
    size_t _target_addrlen;
    size_t _target_straddrlen;
    int _target_family;
};

extern int should_reload;

void free_rr_list(struct rr *root);
struct rr *find_rr(const char *query_name, const size_t query_name_len, const size_t base_name_len, const enum query_type qtype, struct rr *root);
struct rr *find_subdomain_rr(const char *name, const size_t len, const enum query_type qtype, struct rr *root);
int load_resource_records(const char *filename, const int ai_family, char *domain, const char *host_ip, uint32_t ttl, struct rr **rr_list);
int reload_resource_records(const char *filename, const int ai_family, char *domain, const char *host_ip, uint32_t ttl, struct rr **rr_list);
void set_reload_flag(int signal);
#endif