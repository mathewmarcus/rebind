#include <stdlib.h>
#include <string.h>

#include "_rebind_query.h"


void unparse_query_name(const char domain_name[], uint8_t *ns_record, size_t len, size_t label_len) {
    if (!len) {
        ns_record[0] = label_len;
        return;
    } 
    else {
        if (domain_name[0] == '\0')
            ns_record[0] = domain_name[0];
        else if (domain_name[0] == '.') {
            ns_record[0] = label_len;
            label_len = 0;
        }
        else {
            ns_record[0] = domain_name[0];
            label_len++;
        }

        return unparse_query_name(--domain_name, --ns_record, --len, label_len);
    }
}


ssize_t parse_query_name(char query_name[], const uint8_t *query_buf, uint8_t nbytes_remaining, int *error) {
    uint8_t label_len;

    if (!query_buf[0]) {
        *error = 0;
        query_name[0] = '\0';
        return -1;
    } 

    /*
        Invalid domain name, exceeded the max 255 bytes
        https://tools.ietf.org/html/rfc1035#section-2.3.4
    */
    if (!nbytes_remaining) {
        *error = 1;
        return 0;
    }

    label_len = query_buf[0];
    query_name[0] = '.';
    memcpy(query_name + 1, query_buf + 1, label_len);
    return label_len + 1 + parse_query_name(query_name + label_len + 1, query_buf + label_len + 1, nbytes_remaining - label_len, error);
}


ssize_t build_labeled_record(const char domain_name[], uint8_t **ns_record) {
    ssize_t name_len, len;

    name_len = strlen(domain_name);
    len = 1 + name_len + 1;

    if (!(*ns_record = malloc(len)))
        return -1;

    unparse_query_name(domain_name + name_len, (*ns_record) + len - 1, len - 1, 0);

    return len;
}
