#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "_rebind_rr.h"

int should_reload = 0;

static int add_rr(struct rr *root, char *name, const char *target, const uint32_t ttl, const int ai_family);
static int read_resource_records(FILE *file, const int ai_family, char *name, char *target, uint32_t ttl, size_t target_len, const char *format_str, struct rr *rr_list);

void set_reload_flag(int signal) {
    should_reload = 1;
}

int reload_resource_records(const char *filename, const int ai_family, char *domain, const char *host_ip, uint32_t ttl, struct rr **rr_list) {
    free_rr_list(*rr_list);

    return load_resource_records(filename, ai_family, domain, host_ip, ttl, rr_list);
}

int load_resource_records(const char *filename, const int ai_family, char *domain, const char *host_ip, uint32_t ttl, struct rr **rr_list) {
    FILE *f;
    int ret;
    size_t target_len;
    char *name, *target, format_str[13];

    if (!(*rr_list = new_rr(strdup(domain), host_ip, 60, ai_family))) /* Put base domain in front of list */
        return 1;
    (*rr_list)->subdomain_len = 0;

    if (add_rr(*rr_list, strdup("ns1"), host_ip, 60, ai_family) == -1) /* Add ns1 (nameserver) to list */
        return 1;

    if (add_rr(*rr_list, strdup("ns2"), host_ip, 60, ai_family) == -1) /* Add ns2 (nameserver) to list */
        return 1;

    switch (ai_family) {
        case AF_INET:
            target_len = INET_ADDRSTRLEN;
            break;
        case AF_INET6:
            target_len = INET6_ADDRSTRLEN;
            break;
        default:
            fprintf(stderr, "{\"message\": \"Unsupported address family\", \"ai_family\": \"%d\"}\n", ai_family);
            return -1;
    }

    if (!(target = malloc(target_len + 1))) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for resource record target buffer\", \"ai_family\": \"%d\", \"error\": \"%s\"}\n", ai_family, strerror(errno));
        return -1;
    }

    snprintf(format_str, 13, "%%m[^,],%%%ds\n", target_len);
    format_str[12] = '\0';


    if (!(f = fopen(filename, "r"))) {
        free(target);
        fprintf(stderr, "{\"message\": \"Failed to open resource record file\", \"filename\": \"%s\", \"error\": \"%s\"}\n", filename, strerror(errno));
        return -1;
    }

    ret = read_resource_records(f, ai_family, name, target, ttl, target_len, format_str, *rr_list);

    free(target);
    fclose(f);

    return ret;
}

static int read_resource_records(FILE *file, const int ai_family, char *name, char *target, uint32_t ttl, size_t target_len, const char *format_str, struct rr *rr_list) {
    int num_matches;
    name = NULL;

    if ((num_matches = fscanf(file, format_str, &name, target)) == EOF) {
        if (ferror(file)) {
            fprintf(stderr, "{\"message\": \"Read error from resource record file\", \"error\": \"%s\", \"format_str\": \"%s\"}\n", strerror(errno), format_str);
            return -1;
        }
        fprintf(stderr, "{\"message\": \"Read all records from resource record file\"}\n");
        return 0;
    }
    else if (num_matches != 2) {
        fprintf(stderr, "%s\n", name);
        fprintf(stderr, "{\"message\": \"Resource record file is incorrectly formatted\", \"format_str\": \"%s\", \"num_matches\": %d}\n", format_str, num_matches);
        free(name);
        return -1;
    }
    else {
        fprintf(stderr, "{\"message\": \"Adding resource record to list...\", \"ai_family\": \"%d\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, name, target);
        if (add_rr(rr_list, name, target, ttl, ai_family) == -1) {
            return -1;
        }
        fprintf(stderr, "{\"message\": \"Added resource record to list\", \"ai_family\": \"%d\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, name, target);

        return read_resource_records(file, ai_family, name, target, ttl, target_len, format_str, rr_list);
    }
}

struct rr *new_rr(char *name, const char *target, const uint32_t ttl, const int ai_family) {
    struct rr *n;

    if (!(n = malloc(sizeof(struct rr)))) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for resource record node\", \"ai_family\": \"%d\", \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, strerror(errno), name, target);
        return NULL;
    }
    if (inet_pton(ai_family, target, &n->target) != 1) {
        free(n);
        fprintf(stderr, "{\"message\": \"Failed to convert IP from net to ASCII\", \"ai_family\": \"%d\", \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, strerror(errno), name, target);
        return NULL;
    }
    n->name = name;
    n->sent_num_valid = 0;
    n->next = NULL;
    n->subdomain_len = strlen(name) + 1;
    n->ttl = ttl;
    return n;
}


/* This is idempotent */
static int add_rr(struct rr *root, char *name, const char *target, const uint32_t ttl, const int ai_family) {
    struct rr *n;

    if (!root->next) { /* We've reached the end of the list, add the new resource record */
        if (!(n = new_rr(name, target, ttl, ai_family)))
            return -1;
        root->next = n;
        return 0;
    }
    else /* Not at the end of the list yet, continue traversing */
        return add_rr(root->next, name, target, ttl, ai_family);
}

struct rr *find_subdomain_rr(const char *name, const size_t len, struct rr *root) {
    if (!root)
        return NULL;

    if (len == root->subdomain_len && !strncasecmp(name, root->name, root->subdomain_len - 1))
        return root;

    return find_subdomain_rr(name, len, root->next);
}

 void free_rr_list(struct rr *root) {
    if (root) {
        free_rr_list(root->next);
        free(root->name);
        root->name = NULL;
        free(root);
        root = NULL;
    }
    return;
}

struct rr *find_rr(const char *query_name, const size_t query_name_len, const size_t base_name_len, struct rr *root) {
    char *domain;

    if (!strcasecmp(query_name, root->name))
        return root;
    
    if (!(domain = strcasestr(query_name, root->name))) {
        return NULL;
    }
    if (domain[base_name_len] || query_name[query_name_len - base_name_len - 1] != '.') {
        return NULL;
    }
    return find_subdomain_rr(query_name, query_name_len-base_name_len, root);
}