/**
 *   tcprstat -- Extract stats about TCP response times
 *   Copyright (C) 2010  Ignacio Nin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
**/ 

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "functions.h"

#define INITIAL_HASH_SZ     2053
#define MAX_LOAD_PERCENT    65

struct session {
    uint32_t laddr, raddr;
    uint16_t lport, rport;
    
    struct timeval tv;
    
	uint32_t id;
	uint32_t seq;
    struct session *next;
};

struct hash {
    struct session *sessions;
    
    unsigned long sz, count;
        
};

static unsigned long
    hash_fun(uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport);
static int hash_set_internal(struct session *sessions, unsigned long sz,
        uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
        struct timeval tv, struct ip* ip);
static int hash_load_check(struct hash *hash);
static unsigned long hash_newsz(unsigned long sz);
    
unsigned long initial_hash_sz = INITIAL_HASH_SZ;

struct hash *
hash_new(void) {
    struct hash *ret;
    
    ret = malloc(sizeof(struct hash));
    if (!ret)
        abort();
    
    ret->sz = initial_hash_sz;
    ret->count = 0;
    
    // Don't change following ret->sz for initial_hash_sz. That wouldn't be
    // very thread_safe (not that the whole module is :)
    ret->sessions = malloc(ret->sz * sizeof(struct session));
    if (!ret->sessions)
        abort();
    memset(ret->sessions, 0, ret->sz * sizeof(struct session));
    
    return ret;
    
}

void
hash_del(struct hash *hash) {
    free(hash->sessions);
    free(hash);
    
}

int
hash_get(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval *result)
{
    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;
    for (session = hash->sessions + port; session->next; session = session->next)
        if (
            session->next->raddr == laddr &&
            session->next->laddr == raddr &&
            session->next->rport == lport &&
            session->next->lport == rport
        )
        {
            *result = session->next->tv;
            return 1;
            
        }
        
    return 0;
    
}

int
hash_get_rem(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval *result)
{
    struct session *session, *next;
    unsigned long port;

    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;
    for (session = hash->sessions + port; session->next; session = session->next)
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        )
        {
            *result = session->next->tv;
            
            // Now remove
            next = session->next->next;
            free(session->next);
            session->next = next;
            
            hash->count --;
            
            return 1;
            
        }
        
    return 0;
    

}

int
hash_set(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, struct ip *ip)
{
    hash_load_check(hash);
    
    if (hash_set_internal(hash->sessions, hash->sz,
                             laddr, raddr, lport, rport, value, ip))
    {
        hash->count ++;
        return 1;
    }
        
    return 0;
                             
}

int
hash_clean(struct hash *hash, unsigned long min) {
    unsigned long i;
 
    for (i = 0; i < hash->sz; i ++) {
        struct session *session;
        
        for (session = hash->sessions + i; session->next; session = session->next)
            if (session->next->tv.tv_sec * 1000000 + session->next->tv.tv_usec <
                    min)
            {
                struct session *next;
                
                next = session->next->next;
                free(session->next);
                session->next = next;
                
                hash->count --;
                
                // This break is to prevent a segmentation fault when
                // session->next is NULL (session will be null next)
                if (!session->next)
                    break;
                
            }
            
    }
    
    return 0;
    
}

static int
hash_set_session(struct session *sessions, unsigned long sz, 
		struct session *new)
{
	struct session *session;
    unsigned long port;
	uint32_t laddr, raddr;
	uint16_t lport, rport;

	laddr = new->laddr;
	raddr = new->raddr;
	lport = new->lport;
	rport = new->rport;
    port = hash_fun(laddr, raddr, lport, rport) % sz;

    for (session = sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        )
        {
            session->next->tv = new->tv;	
			return 0;
		}
	}

    session->next = malloc(sizeof(struct session));
    if (!session->next)
        abort();
    
    session->next->raddr = raddr;
    session->next->laddr = laddr;
    session->next->rport = rport;
    session->next->lport = lport;
    session->next->tv = new->tv;
	session->next->id = new->id;
	session->next->seq = new->seq;

	return 1;
}

static void
dump_retrans_session(struct session *session, uint32_t bytes, uint32_t delay)
{
	char laddr[16], raddr[16], *addr;
	struct in_addr s;

	s.s_addr = session->laddr;
	addr = inet_ntoa(s);
    strncpy(laddr, addr, 15);
    laddr[15] = '\0';
    
	s.s_addr = session->raddr;
    addr = inet_ntoa(s);
    strncpy(raddr, addr, 15);
    raddr[15] = '\0';


    int off;
    char buf[64];
    struct timeval tv;

    gettimeofday(&tv,NULL);
    off = strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S.",localtime(&tv.tv_sec)); 
    snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
	fprintf(stderr, C_YELLOW"[Retransmit] [%s] %s:%d <==> %s:%d, after %d ms, length %d bytes.\n"C_NONE, 
		buf,
		laddr, session->lport,
		raddr, session->rport, 
		delay, bytes
	);
}

static int
hash_set_internal(struct session *sessions, unsigned long sz,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, struct ip *ip)
{
    struct session *session;
    unsigned long port;
      
    port = hash_fun(laddr, raddr, lport, rport) % sz;

	struct tcphdr *tcp;
	tcp = (struct tcphdr*) ((char*)ip + sizeof(struct ip));
    for (session = sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        )
        {
            struct timeval old = session->next->tv;
            session->next->tv = value;
            
			uint32_t id = ip->ip_id;
			if(id != session->next->id && session->next->seq == tcp->seq) {
            	int delay;
				delay = (value.tv_sec - old.tv_sec) * 1000 + (value.tv_usec - old.tv_usec) / 1000;
				dump_retrans_session(session->next, ntohs(ip->ip_len), delay);
    		}

		 	session->next->id = id;
            return 0;
        }
	}
    
    session->next = malloc(sizeof(struct session));
    if (!session->next)
        abort();
    
    session->next->raddr = raddr;
    session->next->laddr = laddr;
    session->next->rport = rport;
    session->next->lport = lport;
	session->next->id = ip->ip_id;
	session->next->seq = tcp->seq;
    
    session->next->tv = value;
    
    session->next->next = NULL;
    
    return 1;
    
}

static int
hash_load_check(struct hash *hash) {
    if ((hash->count * 100) / hash->sz > MAX_LOAD_PERCENT) {
        struct session *new_sessions, *old_sessions;
        unsigned long nsz, i;
        
        // New container
        nsz = hash_newsz(hash->sz);
        
        new_sessions = malloc(nsz * sizeof(struct session));
        if (!new_sessions)
            abort();
        
        memset(new_sessions, 0, nsz * sizeof(struct session));
        
        // Rehash
        for (i = 0; i < hash->sz; i ++) {
            struct session *session;
            
            for (session = hash->sessions + i; session->next;
                    session = session->next)
            {
                hash_set_session(new_sessions, nsz, session);
            }
            
        }

        // Switch
        hash->sz = nsz;
        old_sessions = hash->sessions;
        hash->sessions = new_sessions;
        free(old_sessions);
        
        return 1;

    }
    
    return 0;
    
}

static unsigned long
hash_fun(uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport) {
    unsigned long ret;
    
#if SIZEOF_UNSIGNED_LONG >= 8
    ret = ((uint64_t) laddr << 32) | raddr;
    ret ^= ((uint64_t) lport << 48) | ((uint64_t) rport << 32) |
            ((uint64_t) lport << 16) | rport;
#elif SIZEOF_UNSIGNED_LONG == 4
    ret = laddr ^ raddr;
    ret ^= (lport << 16) | rport;
#else
#error Cannot determine sizeof(unsigned long)
#endif    

    return ret;

    
}

static unsigned long
hash_newsz(unsigned long sz) {
    return sz * 2 + 1;
    
}
