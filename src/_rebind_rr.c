#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "_rebind_rr.h"
#include "_rebind_query.h"

int should_reload = 0;


static struct rr *new_rr(char *name, char *target, const uint32_t ttl, const enum query_type qtype);
static int add_rr(struct rr *root, char *name, char *target, const uint32_t ttl, const enum query_type qtype);
static int read_resource_records(FILE *file, uint32_t ttl, struct rr *rr_list);

void set_reload_flag(int signal) {
    should_reload = 1;
}

int reload_resource_records(const char *filename, const int ai_family, char *domain, char *host_ip, uint32_t ttl, struct rr **rr_list) {
    free_rr_list(*rr_list);

    return load_resource_records(filename, ai_family, domain, host_ip, ttl, rr_list);
}

int load_resource_records(const char *filename, const int ai_family, char *domain, char *host_ip, uint32_t ttl, struct rr **rr_list) {
    FILE *f;
    int ret;
    enum query_type qtype;

    qtype = ai_family == AF_INET6 ? AAAA : A;

    if (!(*rr_list = new_rr(strdup(domain), strdup(host_ip), 60, qtype))) /* Put base domain in front of list */
        return -1;
    (*rr_list)->subdomain_len = 0;

    if (add_rr(*rr_list, strdup("ns1"), strdup(host_ip), 60, qtype) == -1) /* Add ns1 (nameserver) to list */
        return -1;

    if (add_rr(*rr_list, strdup("ns2"), strdup(host_ip), 60, qtype) == -1) /* Add ns2 (nameserver) to list */
        return -1;


    if (!(f = fopen(filename, "r"))) {
        fprintf(stderr, "{\"message\": \"Failed to open resource record file\", \"filename\": \"%s\", \"error\": \"%s\"}\n", filename, strerror(errno));
        return -1;
    }

    ret = read_resource_records(f, ttl, *rr_list);

    fclose(f);

    return ret;
}

static int read_resource_records(FILE *file, uint32_t ttl, struct rr *rr_list) {
    int num_matches;
    char *name = NULL, qtype_str[6], *target, format_str[13];
    enum query_type qtype;
    size_t target_len;

    if ((num_matches = fscanf(file, "%5[^,],", qtype_str)) == EOF) {
        if (ferror(file)) {
            fprintf(stderr, "{\"message\": \"Read error from resource record file\", \"error\": \"%s\", \"format_str\": \"%s\"}\n", strerror(errno), format_str);
            return -1;
        }
        fprintf(stderr, "{\"message\": \"Read all records from resource record file\"}\n");
        return 0;
    }
    else if (num_matches != 1) {
        fprintf(stderr, "{\"message\": \"Resource record CSV file is incorrectly formatted: Failed to parse query type\", \"num_matches\": %d}\n", num_matches);
        return -1;
    }

    if (!strcmp(qtype_str, "A") && strlen(qtype_str) == 1) {
        qtype = A;
        target_len = INET_ADDRSTRLEN;
    }
    else if (!strcmp(qtype_str, "AAAA")) {
        qtype = AAAA;
        target_len = INET6_ADDRSTRLEN;
    }
    else if (!strcmp(qtype_str, "CNAME")) {
        qtype = CNAME;
        target_len = MAX_NAME_LEN;
    }
    else {
        fprintf(stderr, "{\"message\": \"Unsupported query type in resource record CSV file\", \"queryType\": \"%s\"}\n", qtype_str);
        return -1;
    }

    if (!(target = malloc(target_len + 1))) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for resource record target buffer\", \"ai_family\": %d, \"error\": \"%s\"}\n", qtype, strerror(errno));
        return -1;
    }

    snprintf(format_str, 13, "%%m[^,],%%%ds\n", target_len);
    format_str[12] = '\0';

    if ((num_matches = fscanf(file, format_str, &name, target)) == EOF) {
        if (ferror(file)) {
            fprintf(stderr, "{\"message\": \"Read error from resource record file\", \"error\": \"%s\", \"format_str\": \"%s\"}\n", strerror(errno), format_str);
            return -1;
        }
        fprintf(stderr, "{\"message\": \"Resource record CSV file is incorrectly formatted: Failed to read name and target\", \"error\": \"%s\"}\n", strerror(errno));
        free(target);
        return -1;
    }
    else if (num_matches != 2) {
        fprintf(stderr, "{\"message\": \"Resource record CSV file is incorrectly formatted\", \"format_str\": \"%s\", \"num_matches\": %d}\n", format_str, num_matches);
        free(name);
        free(target);
        return -1;
    }
    else {
        fprintf(stderr, "{\"message\": \"Adding resource record to list...\", \"qtype\": %d, \"name\": \"%s\", \"target\": \"%s\"}\n", qtype, name, target);
        if (add_rr(rr_list, name, target, ttl, qtype) == -1) {
            free(name);
            free(target);
            return -1;
        }
        fprintf(stderr, "{\"message\": \"Added resource record to list\", \"qtype\": %d, \"name\": \"%s\", \"target\": \"%s\"}\n", qtype, name, target);

        return read_resource_records(file, ttl, rr_list);
    }
}

struct rr *new_rr(char *name, char *target, const uint32_t ttl, const enum query_type qtype) {
    struct rr *n;

    if (!(n = malloc(sizeof(struct rr)))) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for resource record node\", \"qtype\": %d, \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", qtype, strerror(errno), name, target);
        return NULL;
    }

    switch (qtype) {
        case A:
            n->_target_family = AF_INET;
            n->_target_addrlen = sizeof(struct in_addr);
            n->_target_straddrlen = INET_ADDRSTRLEN;
            if (inet_pton(n->_target_family, target, &n->target) != 1) {
                free(n);
                fprintf(stderr, "{\"message\": \"Failed to convert IP from net to ASCII\", \"qtype\": %d, \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", qtype, strerror(errno), name, target);
                return NULL;
            }
            break;
        case AAAA:
            n->_target_family = AF_INET6;
            n->_target_addrlen = sizeof(struct in6_addr);
            n->_target_straddrlen = INET6_ADDRSTRLEN;
            if (inet_pton(n->_target_family, target, &n->target) != 1) {
                free(n);
                fprintf(stderr, "{\"message\": \"Failed to convert IP from net to ASCII\", \"qtype\": %d, \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", qtype, strerror(errno), name, target);
                return NULL;
            }
            break;
        case CNAME:
            n->target.name = NULL;
            n->_target_addrlen = build_labeled_record(target, (uint8_t **)&n->target);
            break;
    }

    n->name = name;
    n->sent_num_valid = 0;
    n->next = NULL;
    n->subdomain_len = strlen(name) + 1;
    n->ttl = ttl;
    n->qtype = qtype;
    n->target_str = target;
    return n;
}


/* This is idempotent */
static int add_rr(struct rr *root, char *name, char *target, const uint32_t ttl, const enum query_type qtype) {
    struct rr *n;

    if (!root->next) { /* We've reached the end of the list, add the new resource record */
        if (!(n = new_rr(name, target, ttl, qtype)))
            return -1;
        root->next = n;
        return 0;
    }
    else /* Not at the end of the list yet, continue traversing */
        return add_rr(root->next, name, target, ttl, qtype);
}

struct rr *find_subdomain_rr(const char *name, const size_t len, const enum query_type qtype, struct rr *root) {
    if (!root)
        return NULL;

    if (root->qtype == qtype && len == root->subdomain_len && !strncasecmp(name, root->name, root->subdomain_len - 1))
        return root;

    return find_subdomain_rr(name, len, qtype, root->next);
}

 void free_rr_list(struct rr *root) {
    if (root) {
        free_rr_list(root->next);
        free(root->name);
        root->name = NULL;
        fprintf(stderr, "Freeing target_str %p: %1$s\n", root->target_str);
        free(root->target_str);
        root->target_str = NULL;
        free(root);
        root = NULL;
    }
    return;
}

struct rr *find_rr(const char *query_name, const size_t query_name_len, const size_t base_name_len, const enum query_type qtype, struct rr *root) {
    char *domain;

    if (!strcasecmp(query_name, root->name))
        return root;
    
    if (!(domain = strcasestr(query_name, root->name))) {
        return NULL;
    }
    if (domain[base_name_len] || query_name[query_name_len - base_name_len - 1] != '.') {
        return NULL;
    }
    return find_subdomain_rr(query_name, query_name_len-base_name_len, qtype, root);
}