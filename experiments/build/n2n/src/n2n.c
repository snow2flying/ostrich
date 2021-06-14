/**
 * (C) 2007-21 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n.h"

#include "sn_selection.h"

#include "minilzo.h"

#include <assert.h>



/* ************************************** */

SOCKET open_socket (int local_port, int bind_any, int type /* 0 = UDP, TCP otherwise */) {

    SOCKET sock_fd;
    struct sockaddr_in local_address;
    int sockopt;

    if((sock_fd = socket(PF_INET, ((type == 0) ? SOCK_DGRAM : SOCK_STREAM) , 0)) < 0) {
        traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n",
                   strerror(errno), sock_fd);
        return(-1);
    }

#ifndef WIN32
    /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

    sockopt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(local_port);
    local_address.sin_addr.s_addr = htonl(bind_any ? INADDR_ANY : INADDR_LOOPBACK);

    if(bind(sock_fd,(struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
        traceEvent(TRACE_ERROR, "Bind error on local port %u [%s]\n", local_port, strerror(errno));
        return(-1);
    }

    return(sock_fd);
}


static int traceLevel = 2 /* NORMAL */;
static int useSyslog = 0, syslog_opened = 0;
static FILE *traceFile = NULL;

int getTraceLevel () {

    return(traceLevel);
}

void setTraceLevel (int level) {

    traceLevel = level;
}

void setUseSyslog (int use_syslog) {

    useSyslog = use_syslog;
}

void setTraceFile (FILE *f) {

    traceFile = f;
}

void closeTraceFile () {

    if((traceFile != NULL) && (traceFile != stdout)) {
        fclose(traceFile);
    }
#ifndef WIN32
    if(useSyslog && syslog_opened) {
        closelog();
        syslog_opened = 0;
    }
#endif
}

#define N2N_TRACE_DATESIZE 32
void traceEvent (int eventTraceLevel, char* file, int line, char * format, ...) {

    va_list va_ap;

    if(traceFile == NULL) {
        traceFile = stdout;
    }

    if(eventTraceLevel <= traceLevel) {
        char buf[1024];
        char out_buf[1280];
        char theDate[N2N_TRACE_DATESIZE];
        char *extra_msg = "";
        time_t theTime = time(NULL);
        int i;

        /* We have two paths - one if we're logging, one if we aren't
         * Note that the no-log case is those systems which don't support it(WIN32),
         * those without the headers !defined(USE_SYSLOG)
         * those where it's parametrically off...
         */

        memset(buf, 0, sizeof(buf));
        strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

        va_start(va_ap, format);
        vsnprintf(buf, sizeof(buf) - 1, format, va_ap);
        va_end(va_ap);

        if(eventTraceLevel == 0 /* TRACE_ERROR */) {
            extra_msg = "ERROR: ";
        } else if(eventTraceLevel == 1 /* TRACE_WARNING */) {
            extra_msg = "WARNING: ";
        }

        while(buf[strlen(buf) - 1] == '\n') {
            buf[strlen(buf) - 1] = '\0';
        }

#ifndef WIN32
        if(useSyslog) {
            if(!syslog_opened) {
                openlog("n2n", LOG_PID, LOG_DAEMON);
                syslog_opened = 1;
            }

            snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
            syslog(LOG_INFO, "%s", out_buf);
        } else {
            for(i = strlen(file) - 1; i > 0; i--) {
                if(file[i] == '/') {
                    i++;
                    break;
                }
            }
            snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, &file[i], line, extra_msg, buf);
            fprintf(traceFile, "%s\n", out_buf);
            fflush(traceFile);
        }
#else
        /* this is the WIN32 code */
        for(i = strlen(file) - 1; i > 0; i--) {
            if(file[i] == '\\') {
                i++;
                break;
            }
        }
        snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, &file[i], line, extra_msg, buf);
        fprintf(traceFile, "%s\n", out_buf);
        fflush(traceFile);
#endif
    }

}

/* *********************************************** */

/* addr should be in network order. Things are so much simpler that way. */
char* intoa (uint32_t /* host order */ addr, char* buf, uint16_t buf_len) {

    char *cp, *retStr;
    uint8_t byteval;
    int n;

    cp = &buf[buf_len];
    *--cp = '\0';

    n = 4;
    do {
        byteval = addr & 0xff;
        *--cp = byteval % 10 + '0';
        byteval /= 10;
        if(byteval > 0) {
            *--cp = byteval % 10 + '0';
            byteval /= 10;
            if(byteval > 0) {
                *--cp = byteval + '0';
            }
        }
        *--cp = '.';
        addr >>= 8;
    } while(--n > 0);

    /* Convert the string to lowercase */
    retStr = (char*)(cp + 1);

    return(retStr);
}


/** Convert subnet prefix bit length to host order subnet mask. */
uint32_t bitlen2mask (uint8_t bitlen) {

    uint8_t i;
    uint32_t mask = 0;

    for (i = 1; i <= bitlen; ++i) {
        mask |= 1 << (32 - i);
    }

    return mask;
}


/** Convert host order subnet mask to subnet prefix bit length. */
uint8_t mask2bitlen (uint32_t mask) {

    uint8_t i, bitlen = 0;

    for (i = 0; i < 32; ++i) {
        if((mask << i) & 0x80000000) {
            ++bitlen;
        } else {
            break;
        }
    }

    return bitlen;
}


/* *********************************************** */

char * macaddr_str (macstr_t buf,
                    const n2n_mac_t mac) {

    snprintf(buf, N2N_MACSTR_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
             mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);

    return(buf);
}

/* *********************************************** */

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *  hostname resolution is performed. This could take 15 seconds.
 */
int supernode2sock (n2n_sock_t * sn, const n2n_sn_name_t addrIn) {

    n2n_sn_name_t addr;
    const char *supernode_host;
    int rv = 0;

    memcpy(addr, addrIn, N2N_EDGE_SN_HOST_SIZE);

    supernode_host = strtok(addr, ":");

    if(supernode_host) {
        char *supernode_port = strtok(NULL, ":");
        const struct addrinfo aihints = {0, PF_INET, 0, 0, 0, NULL, NULL, NULL};
        struct addrinfo * ainfo = NULL;
        int nameerr;

        if(supernode_port) {
            sn->port = atoi(supernode_port);
        } else {
            traceEvent(TRACE_WARNING, "Bad supernode parameter (-l <host:port>) %s %s:%s",
                       addr, supernode_host, supernode_port);
        }

        nameerr = getaddrinfo(supernode_host, NULL, &aihints, &ainfo);

        if(0 == nameerr) {
            struct sockaddr_in * saddr;

            /* ainfo s the head of a linked list if non-NULL. */
            if(ainfo && (PF_INET == ainfo->ai_family)) {
                /* It is definitely and IPv4 address -> sockaddr_in */
                saddr = (struct sockaddr_in *)ainfo->ai_addr;

                memcpy(sn->addr.v4, &(saddr->sin_addr.s_addr), IPV4_SIZE);
                sn->family = AF_INET;
            } else {
                /* Should only return IPv4 addresses due to aihints. */
                traceEvent(TRACE_WARNING, "Failed to resolve supernode IPv4 address for %s", supernode_host);
                rv = -1;
            }

            freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */
            ainfo = NULL;
        } else {
            traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s, %d: %s", supernode_host, nameerr, gai_strerror(nameerr));
            rv = -2;
        }

    } else {
        traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
        rv = -3;
    }

    return(rv);
}

/* ************************************** */

struct peer_info* add_sn_to_list_by_mac_or_sock (struct peer_info **sn_list, n2n_sock_t *sock, const n2n_mac_t mac, int *skip_add) {

    struct peer_info *scan, *tmp, *peer = NULL;

    if(!is_null_mac(mac)) { /* not zero MAC */
        HASH_FIND_PEER(*sn_list, mac, peer);
    }

    if(peer == NULL) { /* zero MAC, search by socket */
        HASH_ITER(hh, *sn_list, scan, tmp) {
            if(memcmp(&(scan->sock), sock, sizeof(n2n_sock_t)) == 0) {
                // update mac if appropriate, needs to be deleted first because it is key to the hash list
                if(!is_null_mac(mac)) {
                    HASH_DEL(*sn_list, scan);
                    memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
                    HASH_ADD_PEER(*sn_list, scan);
                }
                peer = scan;
                break;
            }
        }

        if((peer == NULL) && (*skip_add == SN_ADD)) {
            peer = (struct peer_info*)calloc(1, sizeof(struct peer_info));
            if(peer) {
                sn_selection_criterion_default(&(peer->selection_criterion));
                peer->last_valid_time_stamp = initial_time_stamp();
                memcpy(&(peer->sock), sock, sizeof(n2n_sock_t));
                memcpy(peer->mac_addr, mac, sizeof(n2n_mac_t));
                HASH_ADD_PEER(*sn_list, peer);
                *skip_add = SN_ADD_ADDED;
            }
        }
    }

    return peer;
}

/* ************************************************ */


/* http://www.faqs.org/rfcs/rfc908.html */
uint8_t is_multi_broadcast (const n2n_mac_t dest_mac) {

    int is_broadcast = (memcmp(broadcast_mac, dest_mac, N2N_MAC_SIZE) == 0);
    int is_multicast = (memcmp(multicast_mac, dest_mac, 3) == 0) && !(dest_mac[3] >> 7);
    int is_ipv6_multicast = (memcmp(ipv6_multicast_mac, dest_mac, 2) == 0);

    return is_broadcast || is_multicast || is_ipv6_multicast;
}


uint8_t is_broadcast (const n2n_mac_t dest_mac) {

    int is_broadcast = (memcmp(broadcast_mac, dest_mac, N2N_MAC_SIZE) == 0);

    return is_broadcast;
}


uint8_t is_null_mac (const n2n_mac_t dest_mac) {

    int is_null_mac = (memcmp(null_mac, dest_mac, N2N_MAC_SIZE) == 0);

    return is_null_mac;
}


/* *********************************************** */

char* msg_type2str (uint16_t msg_type) {

    switch(msg_type) {
        case MSG_TYPE_REGISTER: return("MSG_TYPE_REGISTER");
        case MSG_TYPE_DEREGISTER: return("MSG_TYPE_DEREGISTER");
        case MSG_TYPE_PACKET: return("MSG_TYPE_PACKET");
        case MSG_TYPE_REGISTER_ACK: return("MSG_TYPE_REGISTER_ACK");
        case MSG_TYPE_REGISTER_SUPER: return("MSG_TYPE_REGISTER_SUPER");
        case MSG_TYPE_REGISTER_SUPER_ACK: return("MSG_TYPE_REGISTER_SUPER_ACK");
        case MSG_TYPE_REGISTER_SUPER_NAK: return("MSG_TYPE_REGISTER_SUPER_NAK");
        case MSG_TYPE_FEDERATION: return("MSG_TYPE_FEDERATION");
        default: return("???");
    }

    return("???");
}

/* *********************************************** */

void hexdump (const uint8_t *buf, size_t len) {

    size_t i;

    if(0 == len) {
        return;
    }

    printf("-----------------------------------------------\n");
    for(i = 0; i < len; i++) {
        if((i > 0) && ((i % 16) == 0)) {
            printf("\n");
        }
        printf("%02X ", buf[i] & 0xFF);
    }
    printf("\n");
    printf("-----------------------------------------------\n");
}


/* *********************************************** */

void print_n2n_version () {

    printf("Welcome to n2n v.%s for %s\n"
           "Built on %s\n"
           "Copyright 2007-2021 - ntop.org and contributors\n\n",
           GIT_RELEASE, PACKAGE_OSNAME, PACKAGE_BUILDDATE);
}

/* *********************************************** */

size_t purge_expired_nodes (struct peer_info **peer_list,
                            SOCKET socket_not_to_close,
                            n2n_tcp_connection_t **tcp_connections,
                            time_t *p_last_purge,
                            int frequency, int timeout) {

    time_t now = time(NULL);
    size_t num_reg = 0;

    if((now - (*p_last_purge)) < frequency) {
        return 0;
    }

    traceEvent(TRACE_DEBUG, "Purging old registrations");

    num_reg = purge_peer_list(peer_list, socket_not_to_close, tcp_connections, now - timeout);

    (*p_last_purge) = now;
    traceEvent(TRACE_DEBUG, "Remove %ld registrations", num_reg);

    return num_reg;
}

/** Purge old items from the peer_list, eventually close the related socket, and
  * return the number of items that were removed. */
size_t purge_peer_list (struct peer_info **peer_list,
                        SOCKET socket_not_to_close,
                        n2n_tcp_connection_t **tcp_connections,
                        time_t purge_before) {

    struct peer_info *scan, *tmp;
    n2n_tcp_connection_t *conn;
    size_t retval = 0;

    HASH_ITER(hh, *peer_list, scan, tmp) {
        if((scan->purgeable == SN_PURGEABLE) && (scan->last_seen < purge_before)) {
            if((scan->socket_fd >=0) && (scan->socket_fd != socket_not_to_close)) {
                if(tcp_connections) {
                    HASH_FIND_INT(*tcp_connections, &scan->socket_fd, conn);
                    if(conn) {
                        HASH_DEL(*tcp_connections, conn);
                        free(conn);
                    }
                    shutdown(scan->socket_fd, SHUT_RDWR);
                    closesocket(scan->socket_fd);
                }
            }
            HASH_DEL(*peer_list, scan);
            retval++;
            free(scan);
        }
    }

    return retval;
}

/** Purge all items from the peer_list and return the number of items that were removed. */
size_t clear_peer_list (struct peer_info ** peer_list) {

    struct peer_info *scan, *tmp;
    size_t retval = 0;

    HASH_ITER(hh, *peer_list, scan, tmp) {
        HASH_DEL(*peer_list, scan);
        retval++;
        free(scan);
    }

    return retval;
}

static uint8_t hex2byte (const char * s) {

    char tmp[3];
    tmp[0] = s[0];
    tmp[1] = s[1];
    tmp[2] = 0; /* NULL term */

    return((uint8_t)strtol(tmp, NULL, 16));
}

extern int str2mac (uint8_t * outmac /* 6 bytes */, const char * s) {

    size_t i;

    /* break it down as one case for the first "HH", the 5 x through loop for
     * each ":HH" where HH is a two hex nibbles in ASCII. */

    *outmac = hex2byte(s);
    ++outmac;
    s += 2; /* don't skip colon yet - helps generalise loop. */

    for(i = 1; i < 6; ++i) {
        s += 1;
        *outmac = hex2byte(s);
        ++outmac;
        s += 2;
    }

    return 0; /* ok */
}

extern char * sock_to_cstr (n2n_sock_str_t out,
                            const n2n_sock_t * sock) {

    if(NULL == out) {
        return NULL;
    }
    memset(out, 0, N2N_SOCKBUF_SIZE);

    if(AF_INET6 == sock->family) {
        /* INET6 not written yet */
        snprintf(out, N2N_SOCKBUF_SIZE, "XXXX:%hu", sock->port);
        return out;
    } else {
        const uint8_t * a = sock->addr.v4;

        snprintf(out, N2N_SOCKBUF_SIZE, "%hu.%hu.%hu.%hu:%hu",
                 (unsigned short)(a[0] & 0xff),
                 (unsigned short)(a[1] & 0xff),
                 (unsigned short)(a[2] & 0xff),
                 (unsigned short)(a[3] & 0xff),
                 (unsigned short)sock->port);
        return out;
    }
}

char *ip_subnet_to_str (dec_ip_bit_str_t buf, const n2n_ip_subnet_t *ipaddr) {

    snprintf(buf, sizeof(dec_ip_bit_str_t), "%hhu.%hhu.%hhu.%hhu/%hhu",
             (uint8_t) ((ipaddr->net_addr >> 24) & 0xFF),
             (uint8_t) ((ipaddr->net_addr >> 16) & 0xFF),
             (uint8_t) ((ipaddr->net_addr >> 8) & 0xFF),
             (uint8_t) (ipaddr->net_addr & 0xFF),
             ipaddr->net_bitlen);

    return buf;
}


/* @return 1 if the two sockets are equivalent. */
int sock_equal (const n2n_sock_t * a,
                const n2n_sock_t * b) {

    if(a->port != b->port) {
        return(0);
    }

    if(a->family != b->family) {
        return(0);
    }

    switch(a->family) {
        case AF_INET:
            if(memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE)) {
                return(0);
            }
            break;

        default:
            if(memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE)) {
                return(0);
            }
            break;
    }

    /* equal */
    return(1);
}

/* *********************************************** */

// fills a specified memory area with random numbers
int memrnd (uint8_t *address, size_t len) {

    for(; len >= 8; len -= 8) {
        *(uint64_t*)address = n2n_rand();
        address += 8;
    }

    for(; len > 0; len--) {
        *address = n2n_rand();
        address++;
    }

    return 0;
}

/* *********************************************** */

#if defined(WIN32)
int gettimeofday (struct timeval *tp, void *tzp) {

    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;

    GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900;
    tm.tm_mon = wtm.wMonth - 1;
    tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour;
    tm.tm_min = wtm.wMinute;
    tm.tm_sec = wtm.wSecond;
    tm.tm_isdst = -1;
    clock = mktime(&tm);
    tp->tv_sec = clock;
    tp->tv_usec = wtm.wMilliseconds * 1000;

    return 0;
}
#endif


// stores the previously issued time stamp
static uint64_t previously_issued_time_stamp = 0;


// returns a time stamp for use with replay protection (branchless code)
//
// depending on the self-detected accuracy, it has the following format
//
// MMMMMMMMCCCCCCCF or
//
// MMMMMMMMSSSSSCCF
//
// with M being the 32-bit second time stamp
//      S       the 20-bit sub-second (microsecond) time stamp part, if applicable
//      C       a counter (8 bit or 24 bit) reset to 0 with every MMMMMMMM(SSSSS) turn-over
//      F       a 4-bit flag field with
//      ...c    being the accuracy indicator (if set, only counter and no sub-second accuracy)
//
uint64_t time_stamp (void) {

    struct timeval tod;
    uint64_t micro_seconds;
    uint64_t co, mask_lo, mask_hi, hi_unchanged, counter, new_co;

    gettimeofday(&tod, NULL);

    // (roughly) calculate the microseconds since 1970, leftbound
    micro_seconds = ((uint64_t)(tod.tv_sec) << 32) + ((uint64_t)tod.tv_usec << 12);
    // more exact but more costly due to the multiplication:
    // micro_seconds = ((uint64_t)(tod.tv_sec) * 1000000ULL + tod.tv_usec) << 12;

    // extract "counter only" flag (lowest bit)
    co = (previously_issued_time_stamp << 63) >> 63;
    // set mask accordingly
    mask_lo   = -co;
    mask_lo >>= 32;
    // either 0x00000000FFFFFFFF (if co flag set) or 0x0000000000000000 (if co flag not set)

    mask_lo  |= (~mask_lo) >> 52;
    // either 0x00000000FFFFFFFF (unchanged)      or 0x0000000000000FFF (lowest 12 bit set)

    mask_hi   = ~mask_lo;

    hi_unchanged = ((previously_issued_time_stamp & mask_hi) == (micro_seconds & mask_hi));
    // 0 if upper bits unchanged (compared to previous stamp), 1 otherwise

    // read counter and shift right for flags
    counter   = (previously_issued_time_stamp & mask_lo) >> 4;

    counter  += hi_unchanged;
    counter  &= -hi_unchanged;
    // either counter++ if upper part of timestamp unchanged, 0 otherwise

    // back to time stamp format
    counter <<= 4;

    // set new co flag if counter overflows while upper bits unchanged or if it was set before
    new_co   = (((counter & mask_lo) == 0) & hi_unchanged) | co;

    // in case co flag changed, masks need to be recalculated
    mask_lo   = -new_co;
    mask_lo >>= 32;
    mask_lo  |= (~mask_lo) >> 52;
    mask_hi   = ~mask_lo;

    // assemble new timestamp
    micro_seconds &= mask_hi;
    micro_seconds |= counter;
    micro_seconds |= new_co;

    previously_issued_time_stamp = micro_seconds;

    return micro_seconds;
}


// returns an initial time stamp for use with replay protection
uint64_t initial_time_stamp (void) {

    return time_stamp() - TIME_STAMP_FRAME;
}


// checks if a provided time stamp is consistent with current time and previously valid time stamps
// and, in case of validity, updates the "last valid time stamp"
int time_stamp_verify_and_update (uint64_t stamp, uint64_t *previous_stamp, int allow_jitter) {

    int64_t diff; /* do not change to unsigned */
    uint64_t co;  /* counter only mode (for sub-seconds) */

    co = (stamp << 63) >> 63;

    // is it around current time (+/- allowed deviation TIME_STAMP_FRAME)?
    diff = stamp - time_stamp();
    // abs()
    diff = (diff < 0 ? -diff : diff);
    if(diff >= TIME_STAMP_FRAME) {
        traceEvent(TRACE_DEBUG, "time_stamp_verify_and_update found a timestamp out of allowed frame.");
        return 0; // failure
    }

    // if applicable: is it higher than previous time stamp (including allowed deviation of TIME_STAMP_JITTER)?
    if(NULL != previous_stamp) {
        diff = stamp - *previous_stamp;
        if(allow_jitter) {
            // 8 times higher jitter allowed for counter-only flagged timestamps ( ~ 1.25 sec with 160 ms default jitter)
            diff += TIME_STAMP_JITTER << (co << 3);
        }

        if(diff <= 0) {
            traceEvent(TRACE_DEBUG, "time_stamp_verify_and_update found a timestamp too old compared to previous.");
            return 0; // failure
        }
        // for not allowing to exploit the allowed TIME_STAMP_JITTER to "turn the clock backwards",
        // set the higher of the values
        *previous_stamp = (stamp > *previous_stamp ? stamp : *previous_stamp);
    }

    return 1; // success
}

/*
===================================================edge=========================================================*/

static int keep_on_running;

#if defined(__linux__) || defined(WIN32)
#ifdef WIN32
BOOL WINAPI term_handler(DWORD sig)
#else
    static void term_handler(int sig)
#endif
{
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "Ok I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "Shutting down...");
        called = 1;
    }

    keep_on_running = 0;
#ifdef WIN32
    return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(WIN32) */


/** Find the address and IP mode for the tuntap device.
 *
 *    s is of the form:
 *
 * ["static"|"dhcp",":"] (<host>|<ip>) [/<cidr subnet mask>]
 *
 * for example        static:192.168.8.5/24
 *
 * Fill the parts of the string into the fileds, ip_mode only if
 * present. All strings are NULL terminated.
 *
 *    return 0 on success and -1 on error
 */
static int scan_address (char * ip_addr, size_t addr_size,
                         char * netmask, size_t netmask_size,
                         char * ip_mode, size_t mode_size,
                         char * s) {

    int retval = -1;
    char * start;
    char * end;
    int bitlen = N2N_EDGE_DEFAULT_CIDR_NM;

    if((NULL == s) || (NULL == ip_addr) || (NULL == netmask)) {
        return -1;
    }

    memset(ip_addr, 0, addr_size);
    memset(netmask, 0, netmask_size);

    start = s;
    end = strpbrk(s, ":");

    if(end) {
        // colon is present
        if(ip_mode) {
            memset(ip_mode, 0, mode_size);
            strncpy(ip_mode, start, (size_t)MIN(end - start, mode_size - 1));
        }
        start = end + 1;
    } else {
        // colon is not present
    }
    // start now points to first address character
    retval = 0; // we have got an address

    end = strpbrk(start, "/");

    if(!end)
        // no slash present -- default end
        end = s + strlen(s);

    strncpy(ip_addr, start, (size_t)MIN(end - start, addr_size - 1)); // ensure NULL term

    if(end) {
        // slash is present

        // now, handle the sub-network address
        sscanf(end + 1, "%u", &bitlen);
        bitlen = htobe32(bitlen2mask(bitlen));
        inet_ntop(AF_INET, &bitlen, netmask, netmask_size);
    }

    return retval;
}

int quick_edge_start(const char *secret,const char *supernode_addr,const char *community_name
,const char *edge_addr,const char *mac) {

    int rc;
    tuntap_dev tuntap;            /* a tuntap device */
    n2n_edge_t *eee;              /* single instance for this program */
    n2n_edge_conf_t conf;         /* generic N2N edge config */
    n2n_tuntap_priv_config_t ec;  /* config used for standalone program execution */
    uint8_t runlevel = 0;         /* bootstrap: runlevel */
    uint8_t seek_answer = 1;      /*            expecting answer from supernode */
    time_t now, last_action = 0;  /*            timeout */
    macstr_t mac_buf;             /*            output mac address */
    fd_set socket_mask;           /*            for supernode answer */
    struct timeval wait_time;     /*            timeout for sn answer */
    peer_info_t *scan, *scan_tmp; /*            supernode iteration */

    uint16_t expected = sizeof(uint16_t);
    uint16_t position = 0;
    uint8_t  pktbuf[N2N_SN_PKTBUF_SIZE + sizeof(uint16_t)]; /* buffer + prepended buffer length in case of tcp */


#ifndef WIN32
    struct passwd *pw = NULL;
#endif
#ifdef HAVE_LIBCAP
    cap_t caps;
#endif
#ifdef WIN32
    initWin32();
#endif

    /* Defaults */
    edge_init_conf_defaults(&conf);
    memset(&ec, 0, sizeof(ec));
    ec.mtu = DEFAULT_MTU;
    ec.daemon = 0;        /* By default run in daemon mode. */

#ifndef WIN32
    if(((pw = getpwnam("n2n")) != NULL) ||
       ((pw = getpwnam("nobody")) != NULL)) {
        ec.userid = pw->pw_uid;
        ec.groupid = pw->pw_gid;
    }
#endif

#ifdef WIN32
    ec.tuntap_dev_name[0] = '\0';
    ec.metric = 0;
#else
    snprintf(ec.tuntap_dev_name, sizeof(ec.tuntap_dev_name), N2N_EDGE_DEFAULT_DEV_NAME);
#endif
    snprintf(ec.netmask, sizeof(ec.netmask), N2N_EDGE_DEFAULT_NETMASK);

/*    if((argc >= 2) && (argv[1][0] != '-')) {
        rc = loadFromFile(argv[1], &conf, &ec);
        if(argc > 2)
            rc = loadFromCLI(argc, argv, &conf, &ec);
    } else if(argc > 1)
        rc = loadFromCLI(argc, argv, &conf, &ec);
    else

#ifdef WIN32
        // load from current directory
        rc = loadFromFile("edge.conf", &conf, &ec);
#else
        rc = -1;
#endif*/
    scan_address(ec.ip_addr, N2N_NETMASK_STR_SIZE,
                                ec.netmask, N2N_NETMASK_STR_SIZE,
                                ec.ip_mode, N2N_IF_MODE_SIZE,
                                edge_addr);
   snprintf((char *)conf.community_name, sizeof(conf.community_name), "%s", community_name); // Community to connect to
   conf.encrypt_key = secret;                                                           // Secret to decrypt & encrypt with
   edge_conf_add_supernode(&conf, supernode_addr);

    if(conf.transop_id == N2N_TRANSFORM_ID_NULL) {
        if(conf.encrypt_key) {
            /* make sure that AES is default cipher if key only (and no cipher) is specified */
            traceEvent(TRACE_WARNING, "Switching to AES as key was provided.");
            conf.transop_id = N2N_TRANSFORM_ID_AES;
        }
    }

/*    if(rc < 0)
        help(0); *//* short help */

//    if(edge_verify_conf(&conf) != 0)
//        rc = -1;
//        return rc;
//        help(0); /* short help */

    traceEvent(TRACE_NORMAL, "Starting n2n edge %s %s", PACKAGE_VERSION, PACKAGE_BUILDDATE);

#if defined(HAVE_OPENSSL_1_1)
    traceEvent(TRACE_NORMAL, "Using %s", OpenSSL_version(0));
#endif

    traceEvent(TRACE_NORMAL, "Using compression: %s.", compression_str(conf.compression));
    traceEvent(TRACE_NORMAL, "Using %s cipher.", transop_str(conf.transop_id));

    /* Random seed */
    n2n_srand (n2n_seed());

#ifndef WIN32
    /* If running suid root then we need to setuid before using the force. */
    if(setuid(0) != 0)
        traceEvent(TRACE_ERROR, "Unable to become root [%u/%s]", errno, strerror(errno));
    /* setgid(0); */
#endif

    if(conf.encrypt_key && !strcmp((char*)conf.community_name, conf.encrypt_key))
        traceEvent(TRACE_WARNING, "Community and encryption key must differ, otherwise security will be compromised");

    if((eee = edge_init(&conf, &rc)) == NULL) {
        traceEvent(TRACE_ERROR, "Failed in edge_init");
        exit(1);
    }
    memcpy(&(eee->tuntap_priv_conf), &ec, sizeof(ec));

    if((0 == strcmp("static", eee->tuntap_priv_conf.ip_mode)) ||
         ((eee->tuntap_priv_conf.ip_mode[0] == '\0') && (eee->tuntap_priv_conf.ip_addr[0] != '\0'))) {
        traceEvent(TRACE_NORMAL, "Use manually set IP address.");
        eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_STATIC;
    } else if(0 == strcmp("dhcp", eee->tuntap_priv_conf.ip_mode)) {
        traceEvent(TRACE_NORMAL, "Obtain IP from other edge DHCP services.");
        eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_DHCP;
    } else {
        traceEvent(TRACE_NORMAL, "Automatically assign IP address by supernode.");
        eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;
    }

    // mini main loop for bootstrap, not using main loop code because some of its mechanisms do not fit in here
    // for the sake of quickly establishing connection. REVISIT when a more elegant way to re-use main loop code
    // is found

    // if more than one supernode given, find at least one who is alive to faster establish connection
    if((HASH_COUNT(eee->conf.supernodes) <= 1) || (eee->conf.connect_tcp)) {
        // skip the initial supernode ping
        traceEvent(TRACE_DEBUG, "Skip PING to supernode.");
        runlevel = 2;
    }

    eee->last_sup = 0; /* if it wasn't zero yet */
    eee->curr_sn = eee->conf.supernodes;
    supernode_connect(eee);

    while(runlevel < 5) {

        now = time(NULL);

        // we do not use switch-case because we also check for 'greater than'

        if(runlevel == 0) { /* PING to all known supernodes */
            last_action = now;
            eee->sn_pong = 0;
            // (re-)initialize the number of max concurrent pings (decreases by calling send_query_peer)
            eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
            send_query_peer(eee, null_mac);
            traceEvent(TRACE_NORMAL, "Send PING to supernodes.");
            runlevel++;
        }

        if(runlevel == 1) { /* PING has been sent to all known supernodes */
            if(eee->sn_pong) {
                // first answer
                eee->sn_pong = 0;
                sn_selection_sort(&(eee->conf.supernodes));
                eee->curr_sn = eee->conf.supernodes;
                supernode_connect(eee);
                traceEvent(TRACE_NORMAL, "Received first PONG from supernode [%s].", eee->curr_sn->ip_addr);
                runlevel++;
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout
                runlevel--;
                // skip waiting for answer to direcly go to send PING again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "PONG timeout.");
            }
        }

        // by the way, have every later PONG cause the remaining (!) list to be sorted because the entries
        // before have already been tried; as opposed to initial PONG, do not change curr_sn
        if(runlevel > 1) {
            if(eee->sn_pong) {
                eee->sn_pong = 0;
                if(eee->curr_sn->hh.next) {
                    sn_selection_sort((peer_info_t**)&(eee->curr_sn->hh.next));
                    traceEvent(TRACE_DEBUG, "Received additional PONG from supernode.");
                    // here, it is hard to detemine from which one, so no details to output
                }
            }
        }

        if(runlevel == 2) { /* send REGISTER_SUPER to get auto ip address from a supernode */
            if(eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
                last_action = now;
                eee->sn_wait = 1;
                send_register_super(eee);
                runlevel++;
                traceEvent(TRACE_NORMAL, "Send REGISTER_SUPER to supernode [%s] asking for IP address.",
                                         eee->curr_sn->ip_addr);
            } else {
                runlevel += 2; /* skip waiting for TUNTAP IP address */
                traceEvent(TRACE_DEBUG, "Skip auto IP address asignment.");
            }
        }

        if(runlevel == 3) { /* REGISTER_SUPER to get auto ip address from a sn has been sent */
            if(!eee->sn_wait) { /* TUNTAP IP address received */
                runlevel++;
                traceEvent(TRACE_NORMAL, "Received REGISTER_SUPER_ACK from supernode for IP address asignment.");
                // it should be from curr_sn, but we can't determine definitely here, so no details to output
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout, so try next supernode
                if(eee->curr_sn->hh.next)
                    eee->curr_sn = eee->curr_sn->hh.next;
                else
                    eee->curr_sn = eee->conf.supernodes;
                supernode_connect(eee);
                runlevel--;
                // skip waiting for answer to direcly go to send REGISTER_SUPER again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK timeout.");
            }
        }

        if(runlevel == 4) { /* configure the TUNTAP device */
            if(tuntap_open(&tuntap, eee->tuntap_priv_conf.tuntap_dev_name, eee->tuntap_priv_conf.ip_mode,
                           eee->tuntap_priv_conf.ip_addr, eee->tuntap_priv_conf.netmask,
                           eee->tuntap_priv_conf.device_mac, eee->tuntap_priv_conf.mtu
#ifdef WIN32
                           , eee->tuntap_priv_conf.metric
#endif
                                                           ) < 0)
                exit(1);
            memcpy(&eee->device, &tuntap, sizeof(tuntap));
            traceEvent(TRACE_NORMAL, "Created local tap device IP: %s, Mask: %s, MAC: %s",
                                     eee->tuntap_priv_conf.ip_addr,
                                     eee->tuntap_priv_conf.netmask,
                                     macaddr_str(mac_buf, eee->device.mac_addr));
            runlevel = 5;
            // no more answers required
            seek_answer = 0;
        }

        // we usually wait for some answer, there however are exceptions when going back to a previous runlevel
        if(seek_answer) {
            FD_ZERO(&socket_mask);
            FD_SET(eee->sock, &socket_mask);
            wait_time.tv_sec = BOOTSTRAP_TIMEOUT;
            wait_time.tv_usec = 0;

            if(select(eee->sock + 1, &socket_mask, NULL, NULL, &wait_time) > 0) {
                if(FD_ISSET(eee->sock, &socket_mask)) {

                    fetch_and_eventually_process_data (eee, eee->sock,
                                                       pktbuf, &expected, &position,
                                                       now);
                }
            }
        }

        seek_answer = 1;
    }
    // allow a higher number of pings for first regular round of ping
    // to quicker get an inital 'supernode selection criterion overview'
    eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
    // shape supernode list; make current one the first on the list
    HASH_ITER(hh, eee->conf.supernodes, scan, scan_tmp) {
        if(scan == eee->curr_sn)
            sn_selection_criterion_good(&(scan->selection_criterion));
        else
            sn_selection_criterion_default(&(scan->selection_criterion));
    }
    sn_selection_sort(&(eee->conf.supernodes));
    // do not immediately ping again, allow some time
    eee->last_sweep = now - SWEEP_TIME + 2 * BOOTSTRAP_TIMEOUT;
    eee->sn_wait = 1;
    eee->last_register_req = 0;

/*#ifndef WIN32
    if(eee->tuntap_priv_conf.daemon) {
        setUseSyslog(1); *//* traceEvent output now goes to syslog. *//*
        daemonize();
    }
#endif *//* #ifndef WIN32 */

#ifndef WIN32

#ifdef HAVE_LIBCAP
    /* Before dropping the privileges, retain capabilities to regain them in future. */
    caps = cap_get_proc();

    cap_set_flag(caps, CAP_PERMITTED, num_cap, cap_values, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if((cap_set_proc(caps) != 0) || (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0))
        traceEvent(TRACE_WARNING, "Unable to retain permitted capabilities [%s]\n", strerror(errno));
#else
#ifndef __APPLE__
    traceEvent(TRACE_WARNING, "n2n has not been compiled with libcap-dev. Some commands may fail.");
#endif
#endif /* HAVE_LIBCAP */

    if((eee->tuntap_priv_conf.userid != 0) || (eee->tuntap_priv_conf.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "Dropping privileges to uid=%d, gid=%d",
                   (signed int)eee->tuntap_priv_conf.userid, (signed int)eee->tuntap_priv_conf.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(eee->tuntap_priv_conf.groupid) != 0)
           || (setuid(eee->tuntap_priv_conf.userid) != 0)) {
            traceEvent(TRACE_ERROR, "Unable to drop privileges [%u/%s]", errno, strerror(errno));
            exit(1);
        }
    }

    if((getuid() == 0) || (getgid() == 0))
        traceEvent(TRACE_WARNING, "Running as root is discouraged, check out the -u/-g options");
#endif

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
#endif
#ifdef WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    keep_on_running = 1;
    traceEvent(TRACE_NORMAL, "edge started");
    rc = run_edge_loop(eee, &keep_on_running);
    print_edge_stats(eee);

#ifdef HAVE_LIBCAP
    /* Before completing the cleanup, regain the capabilities as some
     * cleanup tasks require them (e.g. routes cleanup). */
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if(cap_set_proc(caps) != 0)
        traceEvent(TRACE_WARNING, "Could not regain the capabilities [%s]\n", strerror(errno));

    cap_free(caps);
#endif

    /* Cleanup */
    edge_term_conf(&eee->conf);
    tuntap_close(&eee->device);
    edge_term(eee);

#ifdef WIN32
    destroyWin32();
#endif

    return(rc);
}
/*
===================================================supernode=========================================================*/

static n2n_sn_t sss_node;

#ifdef __linux__
static void dump_registrations (int signo) {

    struct sn_community *comm, *ctmp;
    struct peer_info *list, *tmp;
    char buf[32];
    time_t now = time(NULL);
    u_int num = 0;

    traceEvent(TRACE_NORMAL, "====================================");

    HASH_ITER(hh, sss_node.communities, comm, ctmp) {
        traceEvent(TRACE_NORMAL, "Dumping community: %s", comm->community);

        HASH_ITER(hh, comm->edges, list, tmp) {
            if(list->sock.family == AF_INET) {
	              traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: %u.%u.%u.%u:%u][last seen: %u sec ago]",
		                       ++num, macaddr_str(buf, list->mac_addr),
		                       list->sock.addr.v4[0], list->sock.addr.v4[1], list->sock.addr.v4[2], list->sock.addr.v4[3],
		                       list->sock.port,
		                       now - list->last_seen);
            } else {
	              traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: IPv6:%u][last seen: %u sec ago]",
		                       ++num, macaddr_str(buf, list->mac_addr), list->sock.port,
		                       now - list->last_seen);
            }
        }
    }

    traceEvent(TRACE_NORMAL, "====================================");
}
#endif
/* Add the federation to the communities list of a supernode */
static int add_federation_to_communities (n2n_sn_t *sss) {

    uint32_t    num_communities = 0;

    if(sss->federation != NULL) {
        HASH_ADD_STR(sss->communities, community, sss->federation);

        num_communities = HASH_COUNT(sss->communities);

        traceEvent(TRACE_INFO, "Added federation '%s' to the list of communities [total: %u]",
	                 (char*)sss->federation->community, num_communities);
    }

    return 0;
}

/** Load the list of allowed communities. Existing/previous ones will be removed
 *
 */
static int load_allowed_sn_community (n2n_sn_t *sss) {

    char buffer[4096], *line, *cmn_str, net_str[20];
    dec_ip_str_t ip_str = {'\0'};
    uint8_t bitlen;
    in_addr_t net;
    uint32_t mask;
    FILE *fd = fopen(sss->community_file, "r");
    struct sn_community *s, *tmp;
    uint32_t num_communities = 0;
    struct sn_community_regular_expression *re, *tmp_re;
    uint32_t num_regex = 0;
    int has_net;

    if(fd == NULL) {
        traceEvent(TRACE_WARNING, "File %s not found", sss->community_file);
        return -1;
    }

    HASH_ITER(hh, sss->communities, s, tmp) {
        if(s->is_federation) {
            continue;
        }
        HASH_DEL(sss->communities, s);
        if(NULL != s->header_encryption_ctx) {
            free(s->header_encryption_ctx);
        }
        free(s);
    }

    HASH_ITER(hh, sss->rules, re, tmp_re) {
        HASH_DEL(sss->rules, re);
        free(re);
    }

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        int len = strlen(line);

        if((len < 2) || line[0] == '#') {
            continue;
        }

        len--;
        while(len > 0) {
            if((line[len] == '\n') || (line[len] == '\r')) {
	        line[len] = '\0';
	        len--;
            } else {
	        break;
            }
        }
        // the loop above does not always determine correct 'len'
        len = strlen(line);

        // cut off any IP sub-network upfront
        cmn_str = (char*)calloc(len + 1, sizeof(char));
        has_net = (sscanf(line, "%s %s", cmn_str, net_str) == 2);

        // if it contains typical characters...
        if(NULL != strpbrk(cmn_str, ".*+?[]\\")) {
            // ...it is treated as regular expression
            re = (struct sn_community_regular_expression*)calloc(1,sizeof(struct sn_community_regular_expression));
            if(re) {
                re->rule = re_compile(cmn_str);
                HASH_ADD_PTR(sss->rules, rule, re);
	        num_regex++;
                traceEvent(TRACE_INFO, "Added regular expression for allowed communities '%s'", cmn_str);
                free(cmn_str);
                continue;
            }
        }

        s = (struct sn_community*)calloc(1,sizeof(struct sn_community));

        if(s != NULL) {
            comm_init(s,cmn_str);
            /* loaded from file, this community is unpurgeable */
            s->purgeable = COMMUNITY_UNPURGEABLE;
            /* we do not know if header encryption is used in this community,
             * first packet will show. just in case, setup the key. */
            s->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
            packet_header_setup_key (s->community, &(s->header_encryption_ctx), &(s->header_iv_ctx));
            HASH_ADD_STR(sss->communities, community, s);

            num_communities++;
            traceEvent(TRACE_INFO, "Added allowed community '%s' [total: %u]",
		       (char*)s->community, num_communities);

            // check for sub-network address
            if(has_net) {
                if(sscanf(net_str, "%15[^/]/%hhu", ip_str, &bitlen) != 2) {
                    traceEvent(TRACE_WARNING, "Bad net/bit format '%s' for community '%c', ignoring. See comments inside community.list file.",
		                           net_str, cmn_str);
                    has_net = 0;
                }
                net = inet_addr(ip_str);
                mask = bitlen2mask(bitlen);
                if((net == (in_addr_t)(-1)) || (net == INADDR_NONE) || (net == INADDR_ANY)
	                 || ((ntohl(net) & ~mask) != 0)) {
                    traceEvent(TRACE_WARNING, "Bad network '%s/%u' in '%s' for community '%s', ignoring.",
		                           ip_str, bitlen, net_str, cmn_str);
                    has_net = 0;
                }
                if((bitlen > 30) || (bitlen == 0)) {
                    traceEvent(TRACE_WARNING, "Bad prefix '%hhu' in '%s' for community '%s', ignoring.",
		                           bitlen, net_str, cmn_str);
                    has_net = 0;
                }
            }
            if(has_net) {
                s->auto_ip_net.net_addr = ntohl(net);
                s->auto_ip_net.net_bitlen = bitlen;
                traceEvent(TRACE_INFO, "Assigned sub-network %s/%u to community '%s'.",
		                       inet_ntoa(*(struct in_addr *) &net),
		           s->auto_ip_net.net_bitlen,
		           s->community);
            } else {
                assign_one_ip_subnet(sss, s);
            }
        }

        free(cmn_str);

    }

    fclose(fd);

    if((num_regex + num_communities) == 0) {
        traceEvent(TRACE_WARNING, "File %s does not contain any valid community names or regular expressions", sss->community_file);
        return -1;
    }

    traceEvent(TRACE_NORMAL, "Loaded %u fixed-name communities from %s",
	             num_communities, sss->community_file);

    traceEvent(TRACE_NORMAL, "Loaded %u regular expressions for community name matching from %s",
	             num_regex, sss->community_file);

    /* No new communities will be allowed */
    sss->lock_communities = 1;

    return(0);
}


int quick_super_node_start(int port){
        int rc;
#ifndef WIN32
    struct passwd *pw = NULL;
#endif
    struct peer_info *scan, *tmp;

    setTraceLevel(10);
    sn_init(&sss_node);
    add_federation_to_communities(&sss_node);
    sss_node.lport = port;
    sss_node.daemon = 0;

//     if((argc >= 2) && (argv[1][0] != '-')) {
//         rc = loadFromFile(argv[1], &sss_node);
//         if(argc > 2) {
//             rc = loadFromCLI(argc, argv, &sss_node);
//         }
//     } else if(argc > 1) {
//         rc = loadFromCLI(argc, argv, &sss_node);
//     } else

// #ifdef WIN32
//         // load from current directory
//         rc = loadFromFile("supernode.conf", &sss_node);
// #else
//         rc = -1;
// #endif

//     if(rc < 0) {
//         help(0); /* short help */
//     }

    if(sss_node.community_file)
        load_allowed_sn_community(&sss_node);

#if defined(N2N_HAVE_DAEMON)
    if(sss_node.daemon) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */

        if(-1 == daemon(0, 0)) {
            traceEvent(TRACE_ERROR, "Failed to become daemon.");
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    traceEvent(TRACE_DEBUG, "traceLevel is %d", getTraceLevel());

    sss_node.sock = open_socket(sss_node.lport, 1 /*bind ANY*/, 0 /* UDP */);
    if(-1 == sss_node.sock) {
        traceEvent(TRACE_ERROR, "Failed to open main socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (main)", sss_node.lport);
    }

#ifdef N2N_HAVE_TCP
    sss_node.tcp_sock = open_socket(sss_node.lport, 1 /*bind ANY*/, 1 /* TCP */);
    if(-1 == sss_node.tcp_sock) {
        traceEvent(TRACE_ERROR, "Failed to open auxiliary TCP socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode opened TCP %u (aux)", sss_node.lport);
    }

    if(-1 == listen(sss_node.tcp_sock, N2N_TCP_BACKLOG_QUEUE_SIZE)) {
        traceEvent(TRACE_ERROR, "Failed to listen on auxiliary TCP socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (aux)", sss_node.lport);
    }
#endif

    sss_node.mgmt_sock = open_socket(sss_node.mport, 0 /* bind LOOPBACK */, 0 /* UDP */);
    if(-1 == sss_node.mgmt_sock) {
        traceEvent(TRACE_ERROR, "Failed to open management socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss_node.mport);
    }

    HASH_ITER(hh, sss_node.federation->edges, scan, tmp)
        scan->socket_fd = sss_node.sock;

#ifndef WIN32
    if(((pw = getpwnam ("n2n")) != NULL) || ((pw = getpwnam ("nobody")) != NULL)) {
        sss_node.userid = sss_node.userid == 0 ? pw->pw_uid : 0;
        sss_node.groupid = sss_node.groupid == 0 ? pw->pw_gid : 0;
    }
    if((sss_node.userid != 0) || (sss_node.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "Dropping privileges to uid=%d, gid=%d",
	                 (signed int)sss_node.userid, (signed int)sss_node.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(sss_node.groupid) != 0)
           || (setuid(sss_node.userid) != 0)) {
            traceEvent(TRACE_ERROR, "Unable to drop privileges [%u/%s]", errno, strerror(errno));
            exit(1);
        }
    }

    if((getuid() == 0) || (getgid() == 0)) {
        traceEvent(TRACE_WARNING, "Running as root is discouraged, check out the -u/-g options");
    }
#endif

    traceEvent(TRACE_NORMAL, "supernode started");

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
    signal(SIGHUP,  dump_registrations);
#endif
#ifdef WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    keep_on_running = 1;
    return run_sn_loop(&sss_node, &keep_on_running);
}