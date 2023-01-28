#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

#include "rebind.h"

int get_interface_addr(int socket, char *iface_name, int addr_family, char **addr) {
    size_t str_addrlen;    
    void *iface;
    struct ifreq ipv4_iface;
    struct in6_ifreq ipv6_iface;
    const char *ret;

    strncpy(ipv4_iface.ifr_name, iface_name, IFNAMSIZ);
    if (ioctl(socket, SIOCGIFINDEX, &ipv4_iface) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to determine index of interface\", \"bind_interface\": \"%s\", \"error\": \"%s\"}\n", iface_name, strerror(errno));
        return -1;
    }
    fprintf(stderr, "{\"message\": \"Found index of interface\", \"bind_interface\": \"%s\", \"bind_interface_index\": %i}\n", iface_name, ipv4_iface.ifr_ifindex);

    if (addr_family == AF_INET6) {
        str_addrlen = INET6_ADDRSTRLEN;
        iface = (void *)&ipv6_iface;
        ipv6_iface.ifr6_ifindex = ipv4_iface.ifr_ifindex;
    }
    else {
        str_addrlen = INET_ADDRSTRLEN;
        iface = (void *)&ipv4_iface;
    }

    if (ioctl(socket, SIOCGIFADDR, iface) == -1) {
        fprintf(stderr, "{\"message\": \"Failed to determine IP address of interface\", \"bind_interface\": \"%s\" \"error\": \"%s\"}\n", iface_name, strerror(errno));
        return -1;
    }

    if (!(*addr = malloc(str_addrlen+1))) {
        fprintf(stderr, "{\"message\": \"Failed to allocate memory for interface IP address\", \"bind_interface\": \"%s\", \"error\": \"%s\"}\n", iface_name, strerror(errno));
        return -1;
    }

    if (addr_family == AF_INET6)
        ret = inet_ntop(addr_family, &ipv6_iface.ifr6_addr, *addr, str_addrlen);
    else
        ret = inet_ntop(addr_family, &((struct sockaddr_in *)&ipv4_iface.ifr_addr)->sin_addr, *addr, str_addrlen);

    if (!ret) {
        fprintf(stderr, "{\"message\": \"Failed to convert interface address to ASCII\", \"bind_interface\": \"%s\", \"error\": \"%s\"}\n", iface_name, strerror(errno));
        free(addr);
        return -1;
    }

    fprintf(stderr, "{\"message\": \"Found interface address\", \"bind_interface\": \"%s\", \"bind_interface_addr\": \"%s\"}\n", iface_name, *addr);
    return 0;
}