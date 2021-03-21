#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "rebind.h"

#ifdef CAP_FOUND
#include <sys/capability.h>
#endif


int main(int argc, char *argv[]) {
    int sock, err, domain;
    struct addrinfo hints = {0}, *res = NULL;
    char bind_addr[INET6_ADDRSTRLEN];
    in_port_t bind_port;
    ssize_t nbytes;
    #ifdef CAP_FOUND
    cap_t caps;
    cap_value_t cap_list[1] = { CAP_NET_BIND_SERVICE };
    cap_flag_value_t privileged;
    #endif

    domain = AF_INET; /* TODO: read this from CLI opts via getopt */

    fprintf(stderr, "{\"message\": \"Creating server socket...\"}\n");
    if ((sock = socket(domain, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to create server socket\", \"error\": \"%s\"}\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "{\"message\": \"Successfully created server socket\", \"fd\": %d}\n", sock);

    hints.ai_family = domain,
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
    fprintf(stderr, "{\"message\": \"Retrieved bind address\"}, \"ip\": \"%s\", \"port\": %hu}\n", bind_addr, bind_port);

    #ifdef CAP_FOUND
    if (!(caps = cap_get_proc())) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for process capabilities\", \"error\": \"%s\"}\n", strerror(errno));
        freeaddrinfo(res);
        close(sock);
        return 1;
    }

    /*
        No need to raise capailities in either of the following cases:
            * file effective bit is already sit (e.g. setcap "cap_net_bind_service=ep")
            * file is setuid root (all permitted, inheritable, and effective capabilities bits will already be set)
    */
    if (cap_get_flag(caps, cap_list[0], CAP_EFFECTIVE, &privileged)) {
        fprintf(stderr, "{\"message\": \"Failed to check if CAP_NET_BIND_SERVICE is effective\", \"error\": \"%s\"}\n", strerror(errno));
        cap_free(caps);
        freeaddrinfo(res);
        close(sock);
        return 1;
    }

    if (privileged == CAP_CLEAR) {
        if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
            fprintf(stderr, "{\"message\": \"Failed to set cap flag\", \"error\": \"%s\"}\n", strerror(errno));
            cap_free(caps);
            freeaddrinfo(res);
            close(sock);
            return 1;
        }

        if (cap_set_proc(caps) == -1) {
            fprintf(stderr, "{\"message\": \"Failed to enable CAP_NET_BIND_SERVICE\", \"error\": \"%s\"}\n", strerror(errno));
            cap_free(caps);
            freeaddrinfo(res);
            close(sock);
            return 1;
        }
    }
    cap_free(caps);
    #endif

    fprintf(stderr, "{\"message\": \"Binding server socket to address...\"}, \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n", bind_addr, bind_port, sock);
    if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to bind server socket to address...\"}, \"ip\": \"%s\", \"port\": %hu, \"fd\": %d, \"error\": \"%s\"}\n", bind_addr, bind_port, sock, strerror(errno));
        freeaddrinfo(res);
        close(sock);
        return 1;
    }
    fprintf(stderr, "{\"message\": \"Successfully bound server socket to address\"}, \"ip\": \"%s\", \"port\": %hu, \"fd\": %d}\n", bind_addr, bind_port, sock);
    freeaddrinfo(res);

    #ifdef CAP_FOUND
    if (!(caps = cap_init())) {
        fprintf(stderr, "{\"message\": \"Failed to allocate space for process capabilities\", \"error\": \"%s\"}\n", strerror(errno));
        close(sock);
        return 1;
    }

    if (cap_set_proc(caps) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to drop process capabilities\", \"error\": \"%s\"}\n", strerror(errno));
        cap_free(caps);
        close(sock);
        return 1;
    }
    cap_free(caps);
    #endif


    if (setuid(getuid()) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to permanently drop privileges\", \"error\": \"%s\"}\n", strerror(errno));
        close(sock);
        return 1;
    }

    while (1) {
        //nbytes = recvfrom(sock, )
    }


    close(sock);
    return 0;
}