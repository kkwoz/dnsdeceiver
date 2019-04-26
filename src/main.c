//
// Created by foxtrot_charlie on 18.04.19.
//

/*
 * DNS Deceiver is a small tool in C++ developed by foxtrot_charlie as a uni project.
 * The main goal of this tool is to provide a handy, easy to use and also responsive
 * way of spoofing DNS responses realtime.
 * Unlike other tools like dnspoof, DNS Deceiver enables not only a posibility to be
 * configured by JSON file, but gives a small handy - shell like enviroment with unix
 * like command system. Basic usage:
 *
 * Running the binary (use root priviliages!):
 *      ./dnsdeceiver
 *
 * One can also provide the interface used by dnsdeceiver.
 * If not specified dnsdeceiver will use ALL available and active interfaces.
 *
 * Running dnsdeceiver with given interface:
 *      ./dnsdeceiver wlp3s0
 *
 */

#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("");
    }

    return 0;

}
