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
#include <signal.h>

#include "rebind.h"


int main(int argc, char *argv[]) {
    int sock, err, addr_family = AF_INET;
    struct addrinfo hints = {0}, *res = NULL;
    char query_name[MAX_NAME_LEN], *bind_addr, *remote_addr, *public_target;
    in_port_t bind_port, remote_port;
    size_t ai_addrlen = sizeof(struct in_addr), str_addrlen = INET_ADDRSTRLEN;
    ssize_t nbytes, res_nbytes, base_name_label_len, record_len, base_name_len;
    uint8_t query_buf[BUFLEN], res_buf[BUFLEN], *query_ptr, *res_ptr, *base_name_label, *record_data_ptr;
    uint16_t message_ref;
    uint32_t ttl = 0, valid_response_count = 1;
    struct sockaddr *addr;
    socklen_t addrlen, recv_addrlen;
    struct dns_hdr *query_hdr = (struct dns_hdr *) query_buf, *res_hdr = (struct dns_hdr *) res_buf;
    struct rr *rr_list, *rr;
    sigset_t new_sigs, curr_sigs;
    struct sigaction handler = { 0 };
    enum query_type host_qtype;
    struct in_addr public_a;
    struct in6_addr public_aaaa = IN6ADDR_ANY_INIT;

    public_a.s_addr = INADDR_ANY;

    handler.sa_handler = set_reload_flag;
    if (sigaction(SIGHUP, &handler, NULL) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to set signal handler for SIGHUP\", \"error\": \"%s\"}\n", strerror(errno));
        return 1;
    }

    opterr = 0;
    while((err = getopt(argc, argv, "c:t:6a:A:")) != -1) {
        switch(err) {
            case 'c':
                if (!sscanf(optarg, "%u", &valid_response_count)) {
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
            case 'a':
                if (inet_pton(AF_INET, optarg, &public_a) != 1) {
                    fprintf(stderr, "{\"message\": \"Failed to parse public A record target\", \"arg\": \"%s\"}\n", optarg);
                    return 1;
                }
                break;
            case 'A':
                if (inet_pton(AF_INET6, optarg, &public_aaaa) != 1) {
                    fprintf(stderr, "{\"message\": \"Failed to parse public AAAA record target\", \"arg\": \"%s\"}\n", optarg);
                    return 1;
                }
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
        host_qtype = A;
    }
    else if (res->ai_family == AF_INET6) {
        inet_ntop(res->ai_family, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, bind_addr, res->ai_addrlen);
        bind_port = ntohs(((struct sockaddr_in6 * ) res->ai_addr)->sin6_port);
        host_qtype = AAAA;
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

    if (sigemptyset(&new_sigs) == -1 || sigaddset(&new_sigs, SIGHUP)) {
        fprintf(stderr, "{\"message\": \"Failed to initialize signal set\", \"error\": \"%s\"}\n", strerror(errno));
        free(base_name_label);
        free(addr);
        close(sock);
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
        if ((nbytes = recvfrom(sock, query_ptr, BUFLEN, 0, addr, &recv_addrlen)) == -1 && errno != EINTR) {
            fprintf(stderr, "{\"message\": \"Error while waiting for DNS query\", \"ip\": \"%s\", \"port\": %hu, \"fd\": %d, \"error\": \"%s\"}\n",
                bind_addr,
                bind_port,
                sock,
                strerror(errno));
            free(addr);
            close(sock);
            return 1;
        }
        else if (!nbytes) {
            fprintf(stderr, "{\"message\": \"Received EOF on server socket while waiting for DNS query\"}, \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n",
                bind_addr,
                bind_port,
                sock);
            break;
        }

        if (should_reload) {
            should_reload = 0;
            if (reload_resource_records(argv[optind + 1], addr_family, argv[optind], argv[optind + 2], ttl, &rr_list) == -1)
                break;
            continue;
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

        if (sigprocmask(SIG_BLOCK, &new_sigs, &curr_sigs) == -1) {
            fprintf(stderr, "{\"message\", \"Failed to add SIGHUP to blocked signal mask\", \"error\": \"%s\"}", strerror(errno));
            break;
        }

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

        
        query_ptr += (1 + nbytes + 1); /* skip past the trailing null byte*/
        if (!(rr = find_rr(query_name + 1, nbytes, base_name_len, ntohs(*((uint16_t *)query_ptr)), rr_list))) {
            fprintf(stderr, " \"message\": \"Invalid DNS query: name error\", \"query_name\": \"%s\", \"base_name\": \"%s\", \"qtype\": 0x%02X}\n", query_name + 1, rr_list->name, ntohs(*((uint16_t *)query_ptr)));
            res_hdr->rcode = rcode_name_error;
            goto authoritative_rr;
        } else {
            fprintf(stderr, " \"domain_name\": \"%s\",", query_name);

            public_target = rr->qtype == AAAA ? (char *) &public_aaaa : (char *) &public_a;

            // Compression label

            switch (rr->qtype) {
                case A:
                case AAAA:
                    res_hdr->ancount = htons(0x0001);
                    message_ref = htons(((3 << 6) << 8) | sizeof(struct dns_hdr));
                    record_data_ptr = (uint8_t *)&message_ref;
                    record_len = 2;
                    memcpy(res_ptr, record_data_ptr, record_len);
                    res_ptr += record_len;
                    res_nbytes += record_len;
                    *((uint16_t *)res_ptr) = htons(rr->qtype);
                    res_ptr +=2;
                    res_nbytes += 2;
                    *((uint16_t *)res_ptr) = htons(0x0001);
                    res_ptr +=2;
                    res_nbytes += 2;
                    *((uint32_t *)res_ptr) = htonl(rr->ttl);
                    res_ptr += 4;
                    res_nbytes += 4;
                    *((uint16_t *)res_ptr) = htons(rr->_target_addrlen);
                    res_ptr +=2 ;
                    res_nbytes += 2;

                    fprintf(stderr, " \"is_reserved\": %d,", rr->sent_num_valid);
                    if (rr->sent_num_valid == valid_response_count) {
                        memcpy(res_ptr, &rr->target, rr->_target_addrlen);
                        inet_ntop(rr->_target_family, &rr->target, remote_addr, rr->_target_straddrlen);
                        rr->sent_num_valid = 0;
                    }
                    else {
                        memcpy(res_ptr, public_target, rr->_target_addrlen);
                        inet_ntop(rr->_target_family, public_target, remote_addr, rr->_target_straddrlen);
                        rr->sent_num_valid++;
                    }
                    fprintf(stderr, " \"answer\": \"%s\",", remote_addr);
                    res_ptr += rr->_target_addrlen;
                    res_nbytes += rr->_target_addrlen;

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
                    fprintf(stderr, " \"message\": \"Invalid DNS query: not implemented\", \"qtype\": \"%hu\"}\n", ntohs(*((uint16_t *)query_ptr)));
                    goto authoritative_rr;
            }
        }
        fprintf(stderr, " \"qtype\": \"%hu\",", htons(*((uint16_t *)query_ptr)));
        query_ptr += 2;

        if (ntohs(*((uint16_t *)query_ptr)) != 0x0001) {
            fprintf(stderr, " \"message\": \"Invalid DNS query: not implemented\", \"qclass\": \"%hu\"}\n", ntohs(*((uint16_t *)query_ptr)));
        }
        fprintf(stderr, " \"qclass\": \"%hu\",", ntohs(*((uint16_t *)query_ptr)));
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
        if ((rr = find_subdomain_rr("ns1", 4, host_qtype, rr_list))) {
            res_hdr->arcount = htons(0x0001);
            message_ref = htons(((3 << 6) << 8) | (res_ptr - res_buf));
            record_data_ptr = (uint8_t *)&message_ref;
            res_ptr += 6;
            res_nbytes += 6;
            memcpy(res_ptr, record_data_ptr, record_len);
            res_ptr += 2;
            res_nbytes += 2;
            *((uint16_t *)res_ptr) = htons(rr->qtype);
            res_ptr +=2;
            res_nbytes += 2;
            *((uint16_t *)res_ptr) = htons(0x0001);
            res_ptr +=2;
            res_nbytes += 2;
            *((uint32_t *)res_ptr) = htonl(rr->ttl);
            res_ptr += 4;
            res_nbytes += 4;
            *((uint16_t *)res_ptr) = htons(rr->_target_addrlen);
            res_ptr += 2;
            res_nbytes += 2;
            memcpy(res_ptr, &rr->target, rr->_target_addrlen);
            res_ptr += rr->_target_addrlen;
            res_nbytes += rr->_target_addrlen;
        }
        else
            res_nbytes += 6;

        if ((nbytes = sendto(sock, res_buf, res_nbytes, 0, addr, recv_addrlen)) == -1) {
            fprintf(stderr, "{\"message\": \"Failed to send DNS response\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu, \"message_len\" %lu, \"error\": \"%s\"}\n",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port,
                res_nbytes,
                strerror(errno));
            break;
        }
        if (nbytes != res_nbytes)
            fprintf(stderr, "{\"message\": \"Failed to send all DNS response bytes\", \"server_ip\": \"%s\", \"server_port\": %hu, \"fd\": %d, \"client_ip\": \"%s\", \"client_port\": %hu, \"message_len\" %lu, \"sent_nbytes\": %lu}\n",
                bind_addr,
                bind_port,
                sock,
                remote_addr,
                remote_port,
                res_nbytes,
                nbytes);

        if (sigprocmask(SIG_BLOCK, &curr_sigs, &new_sigs) == -1) {
            fprintf(stderr, "{\"message\", \"Failed to remove SIGHUP from blocked signal mask\", \"error\": \"%s\"}", strerror(errno));
            break;
        }
    }

    free_rr_list(rr_list);
    free(base_name_label);
    free(addr);
    close(sock);
    return 0;
}