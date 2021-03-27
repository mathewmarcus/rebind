#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include "_rebind_rr.h"


static struct rr *new_rr(char *name, const char *target, const int ai_family);
static int read_resource_records(FILE *file, const int ai_family, char *name, char *target, size_t target_len, const char *format_str, struct rr *rr_list);

ssize_t load_resource_records(const char *filename, const int ai_family, struct rr *rr_list) {
    FILE *f;
    ssize_t num_records;
    size_t target_len;
    char *name, *target, format_str[13];

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

    int ret;
    snprintf(format_str, 13, "%%m[^,],%%%ds\n", target_len);
    format_str[12] = '\0';


    if (!(f = fopen(filename, "r"))) {
        free(target);
        fprintf(stderr, "{\"message\": \"Failed to open resource record file\", \"filename\": \"%s\", \"error\": \"%s\"}\n", filename, strerror(errno));
        return -1;
    }

    num_records = read_resource_records(f, ai_family, name, target, target_len, format_str, rr_list);

    free(target);
    fclose(f);

    return num_records;
}

static int read_resource_records(FILE *file, const int ai_family, char *name, char *target, size_t target_len, const char *format_str, struct rr *rr_list) {
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
        if (add_rr(rr_list, name, target, ai_family) == -1) {
            return -1;
        }
        fprintf(stderr, "{\"message\": \"Added resource record to list\", \"ai_family\": \"%d\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, name, target);

        return read_resource_records(file, ai_family, name, target, target_len, format_str, rr_list);
    }
}

static struct rr *new_rr(char *name, const char *target, const int ai_family) {
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
    n->use_restricted = 0;
    n->next = NULL;
    return n;
}


/* This is idempotent */
int add_rr(struct rr *root, char *name, const char *target, const int ai_family) {
    struct rr *n;

    if (!root->name) { /* This is the first node in the list */
        if (inet_pton(ai_family, target, &root->target) != 1) {
            fprintf(stderr, "{\"message\": \"Failed to convert IP from net to ASCII\", \"ai_family\": \"%d\", \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, strerror(errno), name, target);
            return -1;
        }
        root->name = name;
        root->use_restricted = 0;
        root->next = NULL;
    }
    else if (root->name == name) /* This resource record already exists, update target addr */ {
        if (inet_pton(ai_family, target, &root->target) != 1) {
            fprintf(stderr, "{\"message\": \"Failed to convert IP from net to ASCII\", \"ai_family\": \"%d\", \"error\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}\n", ai_family, strerror(errno), name, target);
            return -1;
        }
        root->use_restricted = 0;
        return 0;
    }
    else if (!root->next) { /* We've reached the end of the list, add the new resource record */
        if (!(n = new_rr(name, target, ai_family)))
            return -1;
        root->next = n;
        return 0;
    }
    else /* Not at the end of the list yet, continue traversing */
        return add_rr(root->next, name, target, ai_family);
}