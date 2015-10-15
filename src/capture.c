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

#include "tcprstat.h"
#include "capture.h"
#include "output.h"
#include "util.h"
#include "functions.h"
#include "process-packet.h"

#include <pcap.h>
#include <string.h>

pcap_t *pcap;
struct output_options global_options;

void *
capture(void *arg) {
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[300];
    char ports_str[256];
    char **ports;
    int r, n_ports;

    // Second argument 0 stands for non-promiscuous mode
    pcap = pcap_open_live(global_options.interface, CAPTURE_LENGTH, 0, READ_TIMEOUT, errbuf);
    if (!pcap) {
        LOGGER(ERROR, "pcap: %s\n", errbuf);
        return NULL;
        
    }
    
    if(port) {
        int i, n = 0 ;
        ports = split_string(port, strlen(port), ",", 1, &n_ports);
        if(n_ports > 10) {
            LOGGER(ERROR, "it's unscientific to listen so many ports.\n", errbuf);
            return NULL;
        }
       
        n = snprintf(ports_str, 256, "tcp port %s", ports[0]);
        
        for(i = 1; i < n_ports; i++) {
            n += snprintf(ports_str + n, 256, " or tcp port %s", ports[i]);
        }
        split_string_free(ports, n_ports);
    }

    // Capture only TCP
    if (global_options.server && n_ports) {
        sprintf(filter, "host %s and (%s)", global_options.server, ports_str);
    } else if (global_options.server && !n_ports) {
        sprintf(filter, "host %s", global_options.server);
    } else if (!global_options.server && n_ports) {
        sprintf(filter, " (%s)", ports_str);
    } else {
        sprintf(filter, "tcp");
    }

    if (pcap_compile(pcap, &bpf, filter, 1, 0)) {
        LOGGER(ERROR, "pcap: %s\n", pcap_geterr(pcap));
        return NULL;
        
    }
    
    if (pcap_setfilter(pcap, &bpf)) {
        LOGGER(ERROR, "pcap: %s\n", pcap_geterr(pcap));
        return NULL;
        
    }
    
    // The -1 here stands for "infinity"
    r = pcap_loop(pcap, -1, process_packet, (unsigned char *) pcap);
    if (r == -1) {
        LOGGER(ERROR, "pcap: %s\n", pcap_geterr(pcap));
        return NULL;
        
    }
    
    return NULL;
    
}

int
offline_capture(FILE *fcapture) {
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[300];
    char ports_str[256];
    char **ports;
    int r, n_ports;

    pcap = pcap_fopen_offline(fcapture, errbuf);
    if (!pcap) {
        LOGGER(ERROR, "pcap: %s\n", errbuf);
        return 1;
        
    }
    
    if(port) {
        int i, n = 0 ;
        ports = split_string(port, strlen(port), ",", 1, &n_ports);
        if(n_ports > 10) {
            LOGGER(ERROR, "it's unscientific to listen so many ports.\n", errbuf);
            return 1;
        }
       
        n = snprintf(ports_str, 256, "tcp port %s", ports[0]);
        
        for(i = 1; i < n_ports; i++) {
            n += snprintf(ports_str + n, 256, " or tcp port %s", ports[i]);
        }
        split_string_free(ports, n_ports);
    }

    // Capture only TCP
    if (global_options.server && n_ports) {
        sprintf(filter, "host %s and (%s)", global_options.server, ports_str);
    } else if (global_options.server && !n_ports) {
        sprintf(filter, "host %s", global_options.server);
    } else if (!global_options.server && n_ports) {
        sprintf(filter, "(%s)", ports_str);
    } else {
        sprintf(filter, "tcp");
    }

    if (pcap_compile(pcap, &bpf, filter, 1, 0)) {
        LOGGER(ERROR, "pcap: %s\n", pcap_geterr(pcap));
        return 1;
        
    }
    
    if (pcap_setfilter(pcap, &bpf)) {
        LOGGER(ERROR, "pcap: %s\n", pcap_geterr(pcap));
        return 1;
        
    }
    
    // The -1 here stands for "infinity"
    r = pcap_loop(pcap, -1, process_packet, (unsigned char *) pcap);
    if (r == -1) {
        LOGGER(ERROR, "pcap: %s\n", pcap_geterr(pcap));
        return 1;
        
    }
    
    return 1;
    
}

void
endcapture(void) {
    if (pcap)
        pcap_breakloop(pcap);
    
}
