/*
 * Copyright (C) 2023 Guillaume Pellegrino
 * This file is part of brssh <https://github.com/guillaumepellegrino/brssh>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/ether.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include "process.h"

#define TLV_BRSSH_MIN 0
#define TLV_BRSSH_PACKET 1
#define TLV_BRSSH_MAX 2

typedef struct {
    uint16_t type;
    uint16_t len;
    uint8_t value[24000];
} __attribute__((packed)) tlv_t;

static struct {
    char tuntap[32];
    char inbridge[32];
    char mac[32];
    char ipaddr[64];
    bool dhcp;
} cfg = {
    .tuntap = "tapssh",
    .inbridge = "", // no bridge
    .mac = "", // random mac address
    .dhcp = false,
};
static bool exit_app;

static bool runcmd(const char *argv[]) {
    int pid = 0;

    fprintf(stderr, "Running: ");
    for (size_t i = 0; argv[i]; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    fprintf(stderr, "\n");

    pid = fork();

    if (pid == 0) {
        execvp(argv[0], (char **) argv);
        fprintf(stderr, "Failed to run command %s: %m\n", argv[0]);
        exit(1);
    }
    else if (pid > 0) {
        waitpid(pid, NULL, 0);
        return true;
    }
    else {
        fprintf(stderr, "Failed to fork(): %m\n");
        return false;
    }
}

/**
 * Run ethtool command
 */
static bool ethtool_set(const char *ifname, const char *option, const char *value) {
    const char *argv[] = {"ethtool", "-K", ifname, option, value, NULL};

    if (!runcmd(argv)) {
        fprintf(stderr, "ethtool -K %s %s %s -> failed\n", ifname, option, value);
        fprintf(stderr, "Did you install ethtool ?\n");
        return false;
    }

    return true;
}

/**
 * Disable HW TCP Reassembly using ethtool
 *
 * ethtool -K eno1 tso off
 * ethtool -K eno1 gso off
 * ethtool -K eno1 gro off
 *
 */
static bool ethtool_disable_tcp_reassembly(const char *ifname) {
    bool ret = true;

    ret &= ethtool_set(ifname, "tso", "off");
    ret &= ethtool_set(ifname, "gso", "off");
    ret &= ethtool_set(ifname, "gro", "off");

    return ret;
}

static bool tuntap_add(const char *ifname) {
    const char *argv[] = {"ip", "tuntap", "add", "dev", ifname, "mode", "tap", NULL};
    if (!runcmd(argv)) {
        fprintf(stderr, "Failed to add tuntap interface (%s): %m\n", ifname);
        return false;
    }
    return true;
}

static bool bridge_add(const char *bridge) {
    const char *argv[] = {"brctl", "addbr", bridge, NULL};
    if (!runcmd(argv)) {
        return false;
    }
    return true;
}

static bool bridge_addif(const char *bridge, const char *ifname) {
    const char *argv[] = {"brctl", "addif", bridge, ifname, NULL};
    if (!runcmd(argv)) {
        fprintf(stderr, "Failed to add %s to bridge %s: %m\n", ifname, bridge);
        return false;
    }
    return true;
}

static bool ip_link_bring_up(const char *ifname) {
    const char *argv[] = {"ip", "link", "set", "dev", ifname, "up", NULL};
    if (!runcmd(argv)) {
        fprintf(stderr, "Failed to bring UP tuntap interface (%s): %m\n", ifname);
        return false;
    }
    return true;
}

static bool ip_link_set_mac(const char *ifname, const char *mac) {
    const char *argv[] = {"ip", "link", "set", ifname, "address", mac, NULL};
    if (!runcmd(argv)) {
        fprintf(stderr, "Failed to set MAC Address (%s) for interface (%s): %m\n", mac, ifname);
        return false;
    }
    return true;
}

static bool ifconfig_set_ipaddr(const char *ifname, const char *ipaddr) {
    const char *argv[] = {"ifconfig", ifname, ipaddr, NULL};
    if (!runcmd(argv)) {
        fprintf(stderr, "Failed to set IP Address (%s) for interface (%s): %m\n", ipaddr, ifname);
        return false;
    }
    return true;
}

static void ip_link_delete(const char *ifname) {
    const char *argv[] = {"ip", "link", "del", ifname, NULL};
    runcmd(argv);
}

static int tuntap_open_fd(const char *ifname) {
    int fd = -1;
    struct ifreq ifr = {
        .ifr_flags = IFF_TAP | IFF_NO_PI,
    };

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/net/tun: %m\n");
        return -1;
    }

    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        fprintf(stderr, "Failed to open tuntap interface (%s): %m\n", ifname);
        close(fd);
        return -1;
    }

    return fd;
}

static bool ssh_connect(process_t *process, int ssh_argc, char *ssh_argv[]) {
    const char *argv[128] = {0};
    int argc = 0;

    if (ssh_argc > 120) {
        fprintf(stderr, "Too much ssh arguments\n");
        return false;
    }

    argv[argc++] = "ssh";
    fprintf(stderr, "Running: ssh ");
    for (int i = 0; i < ssh_argc; i++) {
        argv[argc++] = ssh_argv[i];
        fprintf(stderr, "%s ", ssh_argv[i]);
    }
    argv[argc++] = "brssh";
    argv[argc++] = "--server";
    argv[argc] = NULL;
    fprintf(stderr, "brssh --server\n");

    if (!process_start(process, argv)) {
        fprintf(stderr, "Failed to ssh connect: %m\n");
        return false;
    }

    return true;
}

static bool dhcp_client_start(const char *ifname) {
    const char *argv[] = {"dhclient", "-d", ifname, NULL};
    if (!runcmd(argv)) {
        fprintf(stderr, "Failed to run DHCP Client on %s: %m\n", ifname);
        return false;
    }

    return true;
}

static bool brssh_forward_tuntap2ssh(int tuntap, int ssh_input) {
    tlv_t tlv = {0};
    ssize_t rdlen = -1;
    ssize_t wrlen = -1;

    fprintf(stderr, "[%d] Forward tuntap2ssh\n", getpid());
    while (!exit_app) {
        rdlen = read(tuntap, &tlv.value, sizeof(tlv.value));
        if (rdlen < 0) {
            fprintf(stderr, "[%d] Read from tuntap(fd:%d) failed: %m\n", getpid(), tuntap);
            break;
        }
        if (rdlen == 0) {
            fprintf(stderr, "[%d] Read from tuntap(fd:%d) zero\n", getpid(), tuntap);
            break;
        }
        tlv.type = htons(TLV_BRSSH_PACKET);
        tlv.len = htons(rdlen);

        //fprintf(stderr, "[%d] write len=%zd\n", getpid(), rdlen);
        wrlen = write(ssh_input, &tlv, rdlen + 4);
        if (wrlen < 0) {
            fprintf(stderr, "[%d] Write to SSH(fd:%d) failed: %m\n", getpid(), ssh_input);
            break;
        }
        else if (wrlen == 0) {
            fprintf(stderr, "[%d] SSH write pipe(fd:%d) closed\n", getpid(), ssh_input);
            break;
        }
        else if (wrlen != rdlen + 4) {
            fprintf(stderr, "[%d] Could not write whole message (%zu,%zu)\n", getpid(), wrlen, rdlen+4);
            break;
        }
    }
    fprintf(stderr, "[%d] Forward tuntap2ssh, done\n", getpid());

    return true;
}

static void brssh_dump_message(tlv_t *tlv, int fd) {
    uint8_t *u8 = (uint8_t *) tlv;
    ssize_t rdlen = 0;

    fprintf(stderr, "Message: 0x%02x%02x%02x%02x", u8[0], u8[1], u8[2], u8[3]);
    rdlen = read(fd, &tlv->value, 1024);
    if (rdlen <= 0) {
        return;
    }
    for (ssize_t i = 0; i < rdlen; i++) {
        fprintf(stderr, "%02x", tlv->value[i]);
    }
    fprintf(stderr, "\n");
}

static bool read_fixed(int fd, uint8_t *value, int len) {
    ssize_t rdlen = 0;

    while (true) {
        rdlen = read(fd, value, len);
        if (rdlen < 0) {
            fprintf(stderr, "[%d] Read value from SSH(fd:%d) failed: %m\n", getpid(), fd);
            return false;
        }
        else if (rdlen == 0) {
            fprintf(stderr, "[%d] Read value from SSH(fd:%d) failed: closed\n", getpid(), fd);
            return false;
        }
        else if (rdlen == len) {
            return true;
        }

        // still some data to read
        value += rdlen;
        len -= rdlen;
    }
}

static bool brssh_forward_ssh2tuntap(int ssh_output, int tuntap) {
    tlv_t tlv = {0};
    ssize_t rdlen = -1;
    ssize_t wrlen = -1;
    uint16_t tlv_len = 0;
    uint16_t tlv_type = 0;

    fprintf(stderr, "[%d] Forward ssh2tuntap\n", getpid());
    // TODO: Can we merge, the two read syscalls in an unique syscall for perf ?
    while (!exit_app) {
        // Read TLV type/len.
        //fprintf(stderr, "read_header(%d, %p, %u)\n", ssh_output, &tlv, 4);
        if (!read_fixed(ssh_output, (uint8_t *)&tlv, 4)) {
            fprintf(stderr, "[%d] Read from SSH(fd:%d) failed\n", getpid(), ssh_output);
            break;
        }
        tlv_type = ntohs(tlv.type);
        tlv_len = ntohs(tlv.len);
        if (tlv_type <= TLV_BRSSH_MIN || tlv_type >= TLV_BRSSH_MAX) {
            fprintf(stderr, "[%d] Message(%u) is not a brssh message\n", getpid(), tlv_type);
            brssh_dump_message(&tlv, ssh_output);
            break;
        }
        if (tlv_len == 0) {
            fprintf(stderr, "[%d] Message(%u) len is zero\n", getpid(), tlv_type);
            break;
        }
        if (tlv_len > sizeof(tlv.value)) {
            fprintf(stderr, "[%d] Message(%u) len (%u) is too large\n", getpid(), tlv_type, tlv_len);
            break;
        }

        // Read TLV value.
        //fprintf(stderr, "read_value(%d, %p, %u)\n", ssh_output, &tlv.value, tlv_len);
        if (!read_fixed(ssh_output, tlv.value, tlv_len)) {
            fprintf(stderr, "[%d] Read value from SSH(fd:%d) failed\n", getpid(), ssh_output);
            break;
        }

        // Process TLV
        if (tlv_type == TLV_BRSSH_PACKET) {
            wrlen = write(tuntap, &tlv.value, tlv_len);
            if (wrlen < 0) {
                fprintf(stderr, "[%d] Write to tuntap(fd:%d) failed: %m\n", getpid(), tuntap);
                // continue, not a fatal error
            }
        }
        else {
            fprintf(stderr, "Unknown TLV type: %d (len:%d, rdlen:%zd)\n", tlv_type, tlv_len, rdlen);
        }

    }
    fprintf(stderr, "[%d] Forward ssh2tuntap, done\n", getpid());

    return true;
}

static bool brssh_event_loop(int ssh_input, int ssh_output, int tuntap) {
    bool rt = true;
    int wstatus = 0;
    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: %m\n");
        return false;
    }
    else if (pid == 0) {
        // child process
        if (!brssh_forward_tuntap2ssh(tuntap, ssh_input)) {
            printf("[%d] exit(1)\n", getpid());
            exit(1);
        }
            printf("[%d] exit(0)\n", getpid());
        exit(0);
    }
    else {
        // parent process
        rt = brssh_forward_ssh2tuntap(ssh_output, tuntap);
        kill(pid, SIGTERM);
        waitpid(pid, &wstatus, 0);

        printf("[%d] child %d exited\n", getpid(), pid);
        if (!WIFEXITED(wstatus)) {
            fprintf(stderr, "child process terminated unexpectedly\n");
            rt = false;
        }
        if (WEXITSTATUS(wstatus) != 0) {
            fprintf(stderr, "child process exited with error %d\n", WEXITSTATUS(wstatus));
        }
        rt &= (WEXITSTATUS(wstatus) == 0);

        return rt;
    }

    return true;
}

static bool brssh_parse_config(const char *path) {
    char line[4096];
    FILE *fp = NULL;
    char *key = NULL;
    char *value = NULL;
    const char *sep = " \t\r\n";
    int num = 0;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open %s: %m\n", path);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        key = strtok(line, sep);
        value = strtok(NULL, sep);
        num++;

        if (!key || *key == 0 || *key == '#') {
            // empty line or comment
            continue;
        }
        if (!value) {
            fprintf(stderr, "No value defined for %s in %s at line %d\n", key, path, num);
            continue;
        }

        if (!strcmp(key, "tuntap")) {
            snprintf(cfg.tuntap, sizeof(cfg.tuntap), "%s", value);
        }
        else if (!strcmp(key, "inbridge")) {
            snprintf(cfg.inbridge, sizeof(cfg.inbridge), "%s", value);
        }
        else if (!strcmp(key, "mac")) {
            snprintf(cfg.mac, sizeof(cfg.mac), "%s", value);
        }
        else if (!strcmp(key, "ipaddr")) {
            snprintf(cfg.ipaddr, sizeof(cfg.ipaddr), "%s", value);
        }
        else if (!strcmp(key, "dhcp") && !strcmp(value, "true")) {
            cfg.dhcp = true;
        }
    }

    fclose(fp);
    return true;
}

static bool brssh_network_configure(const char *cfg_path) {
    const char *ip_iface = NULL;

    if (!brssh_parse_config(cfg_path)) {
        goto error_config;
    }
    ip_iface = *cfg.inbridge ? cfg.inbridge : cfg.tuntap;
    if (!tuntap_add(cfg.tuntap)) {
        goto error_tuntap;
    }
    if (*cfg.mac) {
        if (!ip_link_set_mac(cfg.tuntap, cfg.mac)) {
            goto error_unconfigure;
        }
    }
    if (!ethtool_disable_tcp_reassembly(cfg.tuntap)) {
        fprintf(stderr, "Failed to disable TCP reassembly for interface (%s)\n", cfg.tuntap);
        goto error_unconfigure;
    }
    if (!ip_link_bring_up(cfg.tuntap)) {
        goto error_unconfigure;
    }

    if (*cfg.inbridge) {
        bridge_add(cfg.inbridge); // may fail if bridge already exist
        if (!bridge_addif(cfg.inbridge, cfg.tuntap)) {
            goto error_unconfigure;
        }
        if (!ethtool_disable_tcp_reassembly(cfg.inbridge)) {
            fprintf(stderr, "Failed to disable TCP reassembly for interface (%s)\n", cfg.inbridge);
            goto error_unconfigure;
        }
        if (!ip_link_bring_up(cfg.inbridge)) {
            goto error_unconfigure;
        }
    }

    if (*cfg.ipaddr) {
        ifconfig_set_ipaddr(ip_iface, cfg.ipaddr);
    }
    else if (cfg.dhcp) {
        dhcp_client_start(ip_iface);
    }

    return true;

error_unconfigure:
    ip_link_delete(cfg.tuntap);
error_tuntap:
error_config:
    return false;
}

/** 
 * Bring up the ssh tunnel on server side
 *  - Configure server network interfaces (tuntap+bridge)
 *  - Open tuntap interface
 *  - Enter Event loop
 *  (Packets are received on stdin and sent on stdout)
 */
static bool brssh_server() {
    bool rt = false;
    int tuntap = -1;

    if (geteuid() != 0) {
        fprintf(stderr, "brssh client must be started with root EUID\n");
        goto error_euid;
    }
    if (!brssh_network_configure("/etc/brssh/server.cfg")) {
        goto error_config;
    }
    tuntap = tuntap_open_fd(cfg.tuntap);
    if (tuntap < 0) {
        goto error_tuntap_open;
    }
    rt = brssh_event_loop(1, 0, tuntap);

    close(tuntap);
error_tuntap_open:
    ip_link_delete(cfg.tuntap);
error_config:
error_euid:
    return rt;
}

/**
 * Bring up the ssh tunnel on client side
 *  - Configure client network interfaces (tuntap+bridge)
 *  - Open tuntap interface
 *  - Spawn 'ssh user@hostname brssh --server' command.
 *    => This is our tunnel
 *  - Enter event loop
 *  (Packets are received and sent on ssh tunnel)
 */
static bool brssh_client(int ssh_argc, char *ssh_argv[]) {
    bool rt = false;
    int tuntap = -1;
    process_t ssh = {0};

    if (geteuid() != 0) {
        fprintf(stderr, "brssh client must be started with root EUID\n");
        goto error_euid;
    }
    if (!brssh_network_configure("/etc/brssh/client.cfg")) {
        goto error_config;
    }
    tuntap = tuntap_open_fd(cfg.tuntap);
    if (tuntap < 0) {
        goto error_tuntap_open;
    }
    if (!ssh_connect(&ssh, ssh_argc, ssh_argv)) {
        goto error_ssh;
    }
    rt = brssh_event_loop(ssh.input, ssh.output, tuntap);

    process_stop(&ssh);
error_ssh:
    close(tuntap);
error_tuntap_open:
    ip_link_delete(cfg.tuntap);
error_config:
error_euid:
    return rt;
}

static void signal_exit_handler(int s) {
    (void) s;

    exit_app = true;

    fprintf(stderr, "[%d] Exit application\n", getpid());
}

static void help() {
    fprintf(stderr,
        "Usage: brssh [SSH_OPTIONS]... user@hostname\n"
        "Bridge two interfaces over ssh\n"
        "Configuration is read from /etc/brssh/{client,server}.cfg\n"
        "\n"
    );
}

int main(int argc, char *argv[]) {
    /*
    const char *short_options = "+shV";
    const struct option long_options[] = {
        {"server",      no_argument,        0, 's'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };
    int opt = -1;
    */
    const struct sigaction action = {
        .sa_handler = signal_exit_handler,
    };

    int rt = 1;

    /*
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                return brssh_server();
            case 'v':
                version();
                return 0;
            case 'h':
                help();
                return 0;
            default:
                break;
        }
    }

    if (argc <= optind) {
        help();
        return 1;
    }
    */

    if (argc <= 1) {
        help();
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    assert(sigaction(SIGINT, &action, NULL) == 0);
    assert(sigaction(SIGQUIT, &action, NULL) == 0);
    assert(sigaction(SIGTERM, &action, NULL) == 0);

    if (!strcmp(argv[1], "--server")) {
        return brssh_server();
    }
    rt = brssh_client(argc-1, argv+1);

    return rt;
}
