#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "rebind.h"

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


int main(int argc, char *argv[]) {
    int sock, err, addr_family = AF_INET;
    struct addrinfo hints = {0}, *res = NULL;
    char query_name[MAX_NAME_LEN], *bind_addr, *remote_addr;
    in_port_t bind_port, remote_port;
    size_t ai_addrlen = sizeof(struct in_addr), str_addrlen = INET_ADDRSTRLEN;
    ssize_t nbytes, res_nbytes, base_name_label_len, record_len, base_name_len;
    uint8_t query_buf[BUFLEN], res_buf[BUFLEN], *query_ptr, *res_ptr, *base_name_label, *record_data_ptr;
    uint16_t message_ref;
    uint32_t ttl = 0, interval = 1;
    struct sockaddr *addr;
    socklen_t addrlen, recv_addrlen;
    struct dns_hdr *query_hdr = (struct dns_hdr *) query_buf, *res_hdr = (struct dns_hdr *) res_buf;
    struct rr *rr_list, *rr;

    opterr = 0;

    while((err = getopt(argc, argv, "r:t:6")) != -1) {
        switch(err) {
            case 'r':
                if (!sscanf(optarg, "%u", &interval)) {
                    fprintf(stderr, USAGE, argv[0]);
                    return 1;
                }
                break;
            case 't':
                if (!sscanf(optarg, "%u", &ttl)) {
                    fprintf(stderr, USAGE, argv[0]);
                    return 1;
                }
                break;
            case '6':
                addr_family = AF_INET6;
                ai_addrlen = sizeof(struct in6_addr);
                str_addrlen = INET6_ADDRSTRLEN;
                break;
            case '?':
            default:
                fprintf(stderr, USAGE, argv[0]);
                return 1;
        }
    }

    if (argc - optind != 3) {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    if (!(bind_addr = malloc(str_addrlen)))
        return 1;
    if (!(remote_addr = malloc(str_addrlen))) {
        free(bind_addr);
        return 1;
    }

    base_name_len = strlen(argv[optind]);

    fprintf(stderr, "{\"message\": \"Creating server socket...\"}\n");
    if ((sock = socket(addr_family, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to create server socket\", \"error\": \"%s\"}\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "{\"message\": \"Successfully created server socket\", \"fd\": %d}\n", sock);

    hints.ai_family = addr_family,
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    fprintf(stderr, "{\"message\": \"Retrieving bind address...\"}\n");
    if ((err = getaddrinfo(NULL, "domain", &hints, &res))) {
        fprintf(stderr, "{\"message\": \"Failed to retrieve bind address\", \"error\": \"%d\"}\n", err);
        close(sock);
        return 1;
    }
    if (res->ai_family == AF_INET) {
        inet_ntop(res->ai_family, &((struct sockaddr_in * ) res->ai_addr)->sin_addr, bind_addr, res->ai_addrlen);
        bind_port = ntohs(((struct sockaddr_in * ) res->ai_addr)->sin_port);
    }
    else if (res->ai_family == AF_INET6) {
        inet_ntop(res->ai_family, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, bind_addr, res->ai_addrlen);
        bind_port = ntohs(((struct sockaddr_in6 * ) res->ai_addr)->sin6_port);
    }
    else {
        fprintf(stderr, "{\"message\": \"Unsupported address type family returned from getaddrinfo()\", \"ai_family\": \"%d\"}\n", res->ai_family);
        freeaddrinfo(res);
        close(sock);
        return 1;
    }
    fprintf(stderr, "{\"message\": \"Retrieved bind address\", \"ip\": \"%s\", \"port\": %hu}\n", bind_addr, bind_port);
    addrlen = res->ai_addrlen;

    #ifdef CAP_FOUND
    if (raise_privs()) {
        freeaddrinfo(res);
        close(sock);
        return 1;
    }
    #endif

    fprintf(stderr, "{\"message\": \"Binding server socket to address...\", \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n", bind_addr, bind_port, sock);
    if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to bind server socket to address...\", \"ip\": \"%s\", \"port\": %hu, \"fd\": %d, \"error\": \"%s\"}\n", bind_addr, bind_port, sock, strerror(errno));
        freeaddrinfo(res);
        close(sock);
        return 1;
    }
    fprintf(stderr, "{\"message\": \"Successfully bound server socket to address\", \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n", bind_addr, bind_port, sock);
    freeaddrinfo(res);

    if (drop_privs()) {
        close(sock);
        return 1;
    }

    if (!(addr = malloc(addrlen))) {
        fprintf(stderr, "{\"message\": \"Failed to allocate buffer for remote addr\", \"addrlen\": %d, \"error\": \"%s\"}\n", addrlen, strerror(errno));
        close(sock);
        return 1;
    }

    if ((base_name_label_len = build_labeled_record(argv[optind], &base_name_label)) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to allocate buffer for labeled base domain record\", \"error\": \"%s\"}\n", strerror(errno));
        free(addr);
        close(sock);
        return 1;
    }
    
    if (load_resource_records(argv[optind + 1], addr_family, argv[optind], argv[optind + 2], ttl, &rr_list) == -1) {
        free(base_name_label);
        free(addr);
        close(sock);
        return 1;
    }

    res_hdr->qr = msg_response;
    res_hdr->aa = 1;
    res_hdr->tc = 0;
    res_hdr->ra = 0;
    res_hdr->z = 0;
    while (1) {
        query_ptr = query_buf;
        recv_addrlen = addrlen;
        res_ptr = res_buf + sizeof(struct dns_hdr);
        res_nbytes = sizeof(struct dns_hdr);
        res_hdr->rcode = rcode_success;
        res_hdr->qdcount = res_hdr->ancount = res_hdr->nscount = res_hdr->arcount = 0x0000;
        record_data_ptr = base_name_label;
        record_len = base_name_label_len;
    
        fprintf(stderr, "{\"message\": \"Waiting for DNS query...\", \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n", bind_addr, bind_port, sock);
        if ((nbytes = recvfrom(sock, query_ptr, BUFLEN, 0, addr, &recv_addrlen)) == -1) {
            fprintf(stderr, "{\"message\": \"Error while waiting for DNS query\", \"ip\": \"%s\", \"port\": %hu, \"fd\": %d, \"error\": \"%s\"}\n",
                bind_addr,
                bind_port,
                sock,
                strerror(errno));
            free(addr);
            close(sock);
            return 1;
        }
        if (!nbytes) {
            fprintf(stderr, "{\"message\": \"Received EOF on server socket while waiting for DNS query\"}, \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n",
                bind_addr,
                bind_port,
                sock);
            break;
        }

        switch (addr_family) {
            case AF_INET:
                inet_ntop(addr_family, &((struct sockaddr_in * ) addr)->sin_addr, remote_addr, recv_addrlen);
                remote_port = ntohs(((struct sockaddr_in * ) addr)->sin_port);
                break;
            case AF_INET6:
                inet_ntop(addr_family, &((struct sockaddr_in6 * ) addr)->sin6_addr, remote_addr, recv_addrlen);
                remote_port = ntohs(((struct sockaddr_in6 * ) addr)->sin6_port);
                break;
        }
        fprintf(stderr, "{\"message\": \"Received UDP message from remote\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu, \"message_len\": %lu}\n",
            bind_addr,
            bind_port,
            sock,
            remote_addr,
            remote_port,
            nbytes);

        if (nbytes < sizeof(struct dns_hdr)) {
            fprintf(stderr, "{\"message\": \"UDP message has fewer than DNS header bytes\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu, \"message_len\": %lu, \"expected_len\": %lu}\n",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port,
                nbytes,
                sizeof(struct dns_hdr));
            continue;
        }
        
        query_hdr->qdcount = htons(query_hdr->qdcount);
        if (query_hdr->qr != msg_query || query_hdr->tc || query_hdr->qdcount != 1) {
            res_hdr->rcode = rcode_format_error;
            fprintf(stderr, "{\"message\": \"Invalid DNS request: format error\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu, \"message_len\" %lu, \"qr\": %hhu, \"tc\": %hhu, \"qdcount\": %hu}\n",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port,
                nbytes,
                query_hdr->qr,
                query_hdr->tc,
                query_hdr->qdcount);
            goto authoritative_rr;
        } 
        
        if (query_hdr->opcode != opcode_query) {
            query_hdr->rcode = rcode_not_implemented;
            fprintf(stderr, "{\"message\": \"Invalid DNS request: not implemented\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu, \"message_len\" %lu, \"opcode\": 0x%02X}\n",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port,
                nbytes,
                query_hdr->opcode);
            goto authoritative_rr;
        }

        query_ptr += sizeof(struct dns_hdr);
        nbytes -= sizeof(struct dns_hdr);

        res_hdr->id = query_hdr->id;
        res_hdr->opcode = query_hdr->opcode;
        res_hdr->rd = query_hdr->rd;

        nbytes = parse_query_name(query_name, query_ptr, fmin(nbytes, MAX_NAME_LEN), &err);
        if (err) {
            res_hdr->rcode = rcode_format_error;
            fprintf(stderr, "{\"message\": \"Invalid DNS query: format error (name too long)\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu}\n",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port);
            continue;
        }
        /* length of name + leading label and trailing null byte + qtype + qclass */
        memcpy(res_ptr, query_ptr, nbytes + 2 + 2 + 2);
        res_ptr += nbytes + 2 + 2 + 2;
        res_nbytes += nbytes + 2 + 2 + 2;
        res_hdr->qdcount = htons(0x0001);


        fprintf(stderr, "{\"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu,",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port);
        if (!(rr = find_rr(query_name + 1, nbytes, base_name_len, rr_list))) { /* TODO support subdomains */
            fprintf(stderr, " \"message\": \"Invalid DNS query: name error\", \"query_name\": \"%s\", \"base_name\": \"%s\"}\n", query_name + 1, rr_list->name);
            res_hdr->rcode = rcode_name_error;
            goto authoritative_rr;
        } else {
            fprintf(stderr, " \"domain_name\": \"%s\",", query_name);
            query_ptr += (1 + nbytes + 1); /* skip past the trailing null byte*/

            // Compression label

            switch (htons(*((uint16_t *)query_ptr))) {
                case A:
                    res_hdr->ancount = htons(0x0001);
                    message_ref = htons(((3 << 6) << 8) | sizeof(struct dns_hdr));
                    record_data_ptr = (uint8_t *)&message_ref;
                    record_len = 2;
                    memcpy(res_ptr, record_data_ptr, record_len);
                    res_ptr += record_len;
                    res_nbytes += record_len;
                    *((uint16_t *)res_ptr) = htons(A);
                    res_ptr +=2;
                    res_nbytes += 2;
                    *((uint16_t *)res_ptr) = htons(0x0001);
                    res_ptr +=2;
                    res_nbytes += 2;
                    *((uint32_t *)res_ptr) = htonl(rr->ttl);
                    res_ptr += 4;
                    res_nbytes += 4;
                    *((uint16_t *)res_ptr) = htons(ai_addrlen);
                    res_ptr +=2 ;
                    res_nbytes += 2;
                    if (rr->use_restricted == interval) {
                        memcpy(res_ptr, &rr->target, ai_addrlen);
                        inet_ntop(addr_family, &rr->target, remote_addr, str_addrlen);
                        fprintf(stderr, " \"answer\": \"%s\", \"is_reserved\": %d,", remote_addr, rr->use_restricted);
                        rr->use_restricted = 0;
                    }
                    else {
                        memcpy(res_ptr, &rr_list->target, ai_addrlen);
                        inet_ntop(addr_family, &rr_list->target, remote_addr, str_addrlen);
                        fprintf(stderr, " \"answer\": \"%s\", \"is_reserved\": %d,", remote_addr, rr->use_restricted);
                        rr->use_restricted++;
                    }
                    res_ptr += ai_addrlen;
                    res_nbytes += ai_addrlen;

                    message_ref = htons(((3 << 6) << 8) | sizeof(struct dns_hdr) + rr->subdomain_len);
                    record_data_ptr = (uint8_t *)&message_ref;
                    break;
                /* TODO
                case AAAA:
                    break;
                case CNAME:
                    break;
                case NS:
                    break; 
                */
                default:
                    res_hdr->rcode = rcode_name_error;
                    fprintf(stderr, " \"message\": \"Invalid DNS query: not implemented\", \"qtype\": \"%hu\"}\n", htons(*((uint16_t *)query_ptr)));
                    goto authoritative_rr;
            }
        }
        fprintf(stderr, " \"qtype\": \"%hu\",", htons(*((uint16_t *)query_ptr)));
        query_ptr += 2;

        if (htons(*((uint16_t *)query_ptr)) != 0x0001) {
            fprintf(stderr, " \"message\": \"Invalid DNS query: not implemented\", \"qclass\": \"%hu\"}\n", htons(*((uint16_t *)query_ptr)));
        }
        fprintf(stderr, " \"qclass\": \"%hu\",", htons(*((uint16_t *)query_ptr)));
        query_ptr += 2;

        fprintf(stderr, " \"message\": \"Received valid DNS query\"}\n");

        authoritative_rr:
        /*
            Build Authoriative section            
        */
        res_hdr->nscount = htons(0x0001);
        memcpy(res_ptr, record_data_ptr, record_len);
        res_nbytes += record_len;
        if (record_len > 2) {
            message_ref = htons(((3 << 6) << 8) | res_ptr - res_buf);
            res_ptr += record_len;
            record_data_ptr = (uint8_t *)&message_ref;
            record_len = 2;
        } else {
            res_ptr += record_len;
        }

        *((uint16_t *)res_ptr) = htons(NS);
        res_ptr += 2;
        res_nbytes += 2;
        *((uint16_t *)res_ptr) = htons(0x0001);
        res_ptr +=2;
        res_nbytes += 2;
        *((uint32_t *)res_ptr) = htonl(3600);
        res_ptr += 4;
        res_nbytes += 4;
        *((uint16_t *)res_ptr) = htons(0x0006);
        res_ptr +=2 ;
        res_nbytes += 2;
        *res_ptr = 0x03;
        strcpy(res_ptr + 1, "ns1");
        memcpy(res_ptr + 4, record_data_ptr, record_len);

        /*
            Build Additional section
        */
        if ((rr = find_subdomain_rr("ns1", 4, rr_list))) {
            res_hdr->arcount = htons(0x0001);
            message_ref = htons(((3 << 6) << 8) | (res_ptr - res_buf));
            record_data_ptr = (uint8_t *)&message_ref;
            res_ptr += 6;
            res_nbytes += 6;
            memcpy(res_ptr, record_data_ptr, record_len);
            res_ptr += 2;
            res_nbytes += 2;
            *((uint16_t *)res_ptr) = htons(A);
            res_ptr +=2;
            res_nbytes += 2;
            *((uint16_t *)res_ptr) = htons(0x0001);
            res_ptr +=2;
            res_nbytes += 2;
            *((uint32_t *)res_ptr) = htonl(rr->ttl);
            res_ptr += 4;
            res_nbytes += 4;
            *((uint16_t *)res_ptr) = htons(ai_addrlen);
            res_ptr += 2;
            res_nbytes += 2;
            memcpy(res_ptr, &rr->target, ai_addrlen);
            res_ptr += ai_addrlen;
            res_nbytes += ai_addrlen;
        }
        else
            res_nbytes += 6;

        sendto(sock, res_buf, res_nbytes, 0, addr, recv_addrlen);
    }

    free_rr_list(rr_list);
    free(base_name_label);
    free(addr);
    close(sock);
    return 0;
}