#ifndef REBIND_H
#define REBIND_H

#include <stdint.h>
#include "_rebind_privs.h"
#include "_rebind_rr.h"
#include "_rebind_query.h"

/* https://tools.ietf.org/html/rfc1035#section-2.3.4 */
#define BUFLEN 512 
#define MAX_NAME_LEN 255
#define TTL 1
#define NS_TTL 86400 /* 1 day */
#define USAGE "Usage: %s [-c ${VALID_RESPONSE_COUNT}] [-t ${TTL}] ${DOMAIN_NAME} ${FILENAME} ${HOST_IP}\n"

enum query_type {
    A = 0x0001,
    NS = 0x0002,
    CNAME = 0x0005,
    AAAA = 0x001C
};

enum msg_type {
    msg_query = 0x00,
    msg_response = 0x01
};

enum opcode {
    opcode_query = 0x00,
    opcode_iquery = 0x01,
    opcode_status = 0x02
};

enum rcode {
    rcode_success = 0x00,
    rcode_format_error = 0x01,
    rcode_server_failure = 0x02,
    rcode_name_error = 0x03,
    rcode_not_implemented = 0x04,
    rcode_refused = 0x05
};

struct dns_hdr {
    uint16_t id;

    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t opcode : 4;
    uint8_t qr : 1;

    uint8_t rcode : 4;
    uint8_t cd :1;
    uint8_t ad :1;
    uint8_t z : 1;
    uint8_t ra : 1;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#endif
