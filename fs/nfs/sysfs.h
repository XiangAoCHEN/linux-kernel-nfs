/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Hammerspace Inc
 */

#ifndef __NFS_SYSFS_H
#define __NFS_SYSFS_H

#define CONTAINER_ID_MAXLEN (64)
//== add code, duplicate with fs/nfs/nfs4_fs.h
#define LDB_MAX_FILE_NUM 100

struct nfs_netns_client {
	struct kobject kobject;
	struct net *net;
	const char __rcu *identifier;
};

extern struct kobject *nfs_client_kobj;

extern int nfs_sysfs_init(void);
extern void nfs_sysfs_exit(void);

void nfs_netns_sysfs_setup(struct nfs_net *netns, struct net *net);
void nfs_netns_sysfs_destroy(struct nfs_net *netns);

//== add code
// config file path: /sys/fs/nfs/nfs_filter
// config file1: /sys/fs/nfs/nfs_filter/filter_list
// config file2: /sys/fs/nfs/nfs_filter/filter_list_max_num
extern struct kobject *nfs_filter_kobj;
#endif
