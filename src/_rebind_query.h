#ifndef _REBIND_QUERY_H
#define _REBIND_QUERY_H

#include <stdint.h>
#include <sys/types.h>

void unparse_query_name(const char domain_name[], uint8_t *ns_record, size_t len, size_t label_len);
ssize_t parse_query_name(char query_name[], const uint8_t *query_buf, uint8_t nbytes_remaining, int *error);
ssize_t build_labeled_record(const char domain_name[], uint8_t **ns_record);


#endif