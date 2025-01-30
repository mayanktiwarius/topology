/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP tunnels program\n"
" - Finding xdp_tunnel_if_map via --dev name info\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h> 

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "xdp_tunnels_common.h"

static const struct option_wrapper long_options[] = {
  {{"help",        no_argument,		NULL, 'h' },
    "Show help", false},

  {{"dev",         required_argument,	NULL, 'd' },
    "Operate on device <ifname>", "<ifname>", true},

  {{0, 0, NULL,  0 }}
};

const char *pin_basedir = "/sys/fs/bpf";
const char *pin_netdir = "/sys/class/net";

int main(int argc, char **argv)
{
  const struct bpf_map_info map_expect_if = {
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct tunnelrec),
    .max_entries = MAX_TUNNELS,
  };
  const struct bpf_map_info map_expect_ipv6 = {
    .key_size    = sizeof(struct in6_addr),
    .value_size  = sizeof(struct tunnelrec),
    .max_entries = MAX_TUNNELS,
  };
  struct bpf_map_info info_if = { 0 };
  struct bpf_map_info info_ipv6 = { 0 };
  char pin_dir[PATH_MAX];
  int tunnel_if_map_fd;
  int tunnel_ipv6_map_fd;
  int port_map_fd;
  int len, err;

  __u32 ifindex;
  char buffer[200];
  char ipv6src[50];
  char ipv6dst[50];
  char ifname[50];
  int vlan = 0;
  int phyid = 0;
  int sessionid = 0;
  int i;
  int ret;
  __u64 cookie = 0x8877665544332211;  // TODO actually read cookie from input

  struct config cfg = {
    .ifindex   = -1,
    .do_unload = false,
  };

  struct tunnelrec entry;

  DIR *dr,*dr2;
  struct dirent *de, *de2;
  char path[PATH_MAX];
  FILE *fp;

  /* Cmdline options can change progsec */
  parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

  /* Required option */
  if (cfg.ifindex == -1) {
    fprintf(stderr, "ERR: required option --dev missing\n\n");
    usage(argv[0], __doc__, long_options, (argc == 1));
    return EXIT_FAIL_OPTION;
  }

  /* Use the --dev name as subdir for finding pinned maps */
  len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
  if (len < 0) {
    fprintf(stderr, "ERR: creating pin dirname\n");
    return EXIT_FAIL_OPTION;
  }

  tunnel_if_map_fd = open_bpf_map_file(pin_dir, "xdp_tunnel_if_map", &info_if);
  if (tunnel_if_map_fd < 0) {
    return EXIT_FAIL_BPF;
  }
  tunnel_ipv6_map_fd = open_bpf_map_file(pin_dir, "xdp_tunnel_ipv6_map", &info_ipv6);
  if (tunnel_ipv6_map_fd < 0) {
    return EXIT_FAIL_BPF;
  }

  printf("updating tx_port map ...\n");
  port_map_fd = open_bpf_map_file(pin_dir, "tx_port", NULL);
  if (port_map_fd < 0) {
    return EXIT_FAIL_BPF;
  }

  dr = opendir(pin_netdir);
  if (NULL == dr) {
    fprintf(stderr, "ERR: can't read %s\n", pin_netdir);
    return -1;
  }
  while (NULL != (de = readdir(dr))) {
    if (0 != strcmp(de->d_name, ".") && 0 != strcmp(de->d_name, "..")) {
      strcpy(path, pin_netdir);
      strcat(path, "/");
      strcat(path, de->d_name);
      dr2 = opendir(path);
      if (NULL != dr2) {
        while (NULL != (de2 = readdir(dr2))) {
          if (0 == strcmp(de2->d_name, "ifindex")) {
            strcat(path, "/");
            strcat(path, de2->d_name);
            fp = fopen(path, "r");
            i=0;
            if (fp) {
              fscanf(fp, "%d", &i);
              printf("tx_port: %s(%d)\n", de->d_name, i);
              err = bpf_map_update_elem(port_map_fd, &i, &i, 0);
              if (err) {
                fprintf(stderr, "ERR: bpf_map_update_elem i=%d err=%d\n", i, err);
                return err;
              }
              fclose(fp);
            }
          }
        }
        closedir(dr2);
      }
    }
  }
  closedir(dr);

  /* check map info, e.g. datarec is expected size */
  err = check_map_fd_info(&info_if, &map_expect_if);
  if (err) {
    fprintf(stderr, "ERR: if map via FD not compatible\n");
    return err;
  }
  err = check_map_fd_info(&info_ipv6, &map_expect_ipv6);
  if (err) {
    fprintf(stderr, "ERR: ipv6 map via FD not compatible\n");
    return err;
  }
  if (verbose) {
    printf("\nCollecting tunnels from BPF map\n");
    printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
        " key_size:%d value_size:%d max_entries:%d\n",
        info_if.type, info_if.id, info_if.name,
        info_if.key_size, info_if.value_size, info_if.max_entries
        );
  }

  while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
    //          printf("input=%s\n", buffer);
    ret = sscanf(buffer, "%d %s %s %s %d %d %d", &ifindex, ipv6src, ipv6dst, ifname, &vlan, &phyid, &sessionid);
    //          printf("read %d fields\n", ret);
    if (ret == 7) {
      printf("%s(%d) [vlan %d phyid %d]: l2tp %s -> %s sessionid=%d\n", ifname, ifindex, vlan, phyid, ipv6src, ipv6dst, sessionid);
      if (inet_pton(AF_INET6, ipv6src, &(entry.ipv6_src)) != 1) {
        printf("illegal ipv6 src address: %s\n", ipv6src);
        return err;
      }
      if (inet_pton(AF_INET6, ipv6dst, &(entry.ipv6_dst)) != 1) {
        printf("illegal ipv6 dst address: %s\n", ipv6dst);
        return err;
      }
      if (vlan != -1 && vlan > 4095) {
        printf("illegal vlan id (use 0 for untagged): %d\n", vlan);
        return err;
      }
      if (vlan == -1) {
        entry.vlan = 0;
        vlan = entry.vlan;
      } else {
        entry.vlan = vlan + 0;
      }
      entry.cookie = cookie;
      entry.phyid = phyid;
      entry.session_id = sessionid;
      if (bpf_map_update_elem(tunnel_if_map_fd, &ifindex, &entry, BPF_ANY)) {
        printf("cant add ifindex %d to tunnel_if_map\n", ifindex);
        return err;
      }
      if (bpf_map_update_elem(tunnel_ipv6_map_fd, &(entry.ipv6_dst), &entry, BPF_ANY)) {
        printf("cant add %s to tunnel_ipv6_map\n", ipv6dst);
        return err;
      }
    } else {
      printf("input is garbage\n");
    }
  }

  return EXIT_OK;
}
