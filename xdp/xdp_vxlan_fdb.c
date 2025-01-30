/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP vxlan fdb program\n"
	" - Finding xdp_vxlan_fdb_map via --dev name info\n";

/*

xdp_vxlan_fdb <filename|stdin>

Parse output of FRR vtysh -c "show evpn mac vni all json"

Example input:

{
  "100":{
    "numMacs":4,
    "macs":{
      "7e:1b:c5:bc:40:6a":{
        "type":"local",
        "intf":"br100",
        "vlan":1,
        "localSequence":0,
        "remoteSequence":0,
        "detectionCount":0,
        "isDuplicate":false
      },
      "1a:58:35:6b:3c:83":{
        "type":"remote",
        "remoteVtep":"10.0.1.22",
        "localSequence":0,
        "remoteSequence":0,
        "detectionCount":0,
        "isDuplicate":false
      },
      "22:44:4a:da:d1:a0":{
        "type":"remote",
        "remoteVtep":"10.0.1.21",
        "localSequence":0,
        "remoteSequence":0,
        "detectionCount":0,
        "isDuplicate":false
      },
      "2e:f9:5d:67:fe:56":{
        "type":"local",
        "intf":"eth1",
        "localSequence":0,
        "remoteSequence":0,
        "detectionCount":0,
        "isDuplicate":false
      }
    }
  },
  "200":{
    "numMacs":1,
    "macs":{
      "0a:2f:d7:9e:55:17":{
        "type":"local",
        "intf":"br200",
        "vlan":1,
        "localSequence":0,
        "remoteSequence":0,
        "detectionCount":0,
        "isDuplicate":false
      }
    }
  }
}

Output:

7e:1b:c5:bc:40:6a local 0 br100 (null)
1a:58:35:6b:3c:83 remote 0 (null) 10.0.1.22
22:44:4a:da:d1:a0 remote 0 (null) 10.0.1.21
2e:f9:5d:67:fe:56 local 0 eth1 (null)
0a:2f:d7:9e:55:17 local 0 br200 (null)
*/

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include <bpf/bpf.h> 

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#include <json.h>
#include <json_util.h>

#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "xdp_vxlan_fdb_common.h"

const char *pin_basedir = "/sys/fs/bpf";
const char *pin_netdir = "/sys/class/net";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{0, 0, NULL,  0 }}
};

void print_json_type(struct json_object *obj)
{
  enum json_type type = json_object_get_type(obj);
  printf("type: ");
  switch (type) {
    case json_type_null: printf("json_type_null\n");
      break;
    case json_type_boolean: printf("json_type_boolean\n");
      break;
    case json_type_double: printf("json_type_double\n");
      break;
    case json_type_int: printf("json_type_int\n");
      break;
    case json_type_object: printf("json_type_object\n");
      break;
    case json_type_array: printf("json_type_array\n");
      break;
    case json_type_string: printf("json_type_string\n");
      break;
  }
}

int main(int argc, char **argv)
{
  struct json_object *evpn_obj, *vni_obj, *mac_obj;
  char *macp;

	const struct bpf_map_info map_vxlan_fdb = {
		.key_size    = ETH_ALEN,
		.value_size  = sizeof(struct vxlanfdbrec),
		.max_entries = MAX_VXLAN_FDBS,
	};
	struct bpf_map_info info_vxlan_fdb = { 0 };

	char pin_dir[PATH_MAX];
	char *intf, *vtep;
  int vxlan_fdb_map_fd;
  int port_map_fd, vni;
  int i, len, err;

  __u32 ifindex;

  struct config cfg = {
    .ifindex   = -1,
    .do_unload = false,
  };

  struct vxlanfdbrec entry;
  
  DIR *dr,*dr2;
  struct dirent *de, *de2;
  char path[PATH_MAX];
  FILE *fp;
  unsigned char mac[6];
  char *vtep_source;

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

  vtep_source = argv[3];
  printf("vtep_source=%s\n", vtep_source);

  if (5 == argc) {
    evpn_obj = json_object_from_file(argv[4]);
  } else {
    evpn_obj = json_object_from_fd(0);
  }

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

  vxlan_fdb_map_fd = open_bpf_map_file(pin_dir, "xdp_vxlan_fdb_map", &info_vxlan_fdb);
  if (vxlan_fdb_map_fd < 0) {
    return EXIT_FAIL_BPF;
  }

  err = check_map_fd_info(&info_vxlan_fdb, &map_vxlan_fdb);
  if (err) {
    fprintf(stderr, "ERR: vxlan_fdb map via FD not compatible\n");
    return err;
  }

  printf("before foreach ...\n");
  json_object_object_foreach(evpn_obj, key, val) {
    vni = atoi(key);
    vni_obj = val; 
    mac_obj = json_object_object_get(vni_obj, "macs");
    json_object_object_foreach(mac_obj, key, val) {
      macp = key;
//      printf("key: \"%s\", type of val: ", key);
//      print_json_type(val);
      intf = json_object_get_string(json_object_object_get(val, "intf"));
      vtep = json_object_get_string(json_object_object_get(val, "remoteVtep"));
      ifindex = 0;
      if (intf) {
        ifindex = if_nametoindex(intf); 
      }
      printf("%s %s %d %s %s\n", macp, 
          json_object_get_string(json_object_object_get(val, "type")),
          ifindex,
          json_object_get_string(json_object_object_get(val, "intf")),
          vtep);
      if (vtep) {
        if (inet_pton(AF_INET, vtep, &(entry.ipv4_vtep)) != 1 ) {
          printf("illegal ipv4 vtep address: %s\n", vtep);
          return err;
        }
        if (inet_pton(AF_INET, vtep_source, &(entry.ipv4_srcvtep)) != 1 ) {
          printf("illegal ipv4 vtep source address: %s\n", vtep_source);
          return err;
        }
      }
      entry.vni = vni;
      entry.ifindex = ifindex;
      entry.vlan = 0;

      sscanf(macp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
      memcpy(entry.ether_dest, mac, ETH_ALEN);
//      printf("mac=%x:%x:%x:%x:%x:%x\n", entry.ether_dest[0], entry.ether_dest[1],
//          entry.ether_dest[2], entry.ether_dest[3], entry.ether_dest[4], entry.ether_dest[5]);

      if (bpf_map_update_elem(vxlan_fdb_map_fd, &(entry.ether_dest), &entry, BPF_ANY)) {
        printf("cant add mac %s to vxlan_fdb_map_fd\n", mac);
        return err;
      }         
    } 
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
}
