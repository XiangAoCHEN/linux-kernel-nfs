// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Hammerspace Inc
 */

#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/nfs_fs.h>
#include <linux/rcupdate.h>

#include "nfs4_fs.h"
#include "netns.h"
#include "sysfs.h"

struct kobject *nfs_client_kobj;
static struct kset *nfs_client_kset;
//== add code begin
struct kobject *nfs_filter_kobj;
char *LDB_filter_list[LDB_MAX_FILE_NUM]; // New field for the filter list
size_t LDB_filter_list_max_num = 0;

static ssize_t LDB_filter_list_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	ssize_t count = 0;
	size_t i;
	// config file1: /sys/fs/nfs/nfs_filter/filter_list
	if(strcmp(attr->attr.name, "filter_list") == 0){
		for (i = 0; i < LDB_MAX_FILE_NUM && LDB_filter_list[i]; i++) {
			count += scnprintf(buf + count, PAGE_SIZE - count, "%s\n", LDB_filter_list[i]);
			printk(KERN_INFO "[MY] LDB_filter_list_show %d : %s\n", i, LDB_filter_list[i]);
		}
	}
	// config file2: /sys/fs/nfs/nfs_filter/filter_list_max_num

	return count;
}
// each line a string
static ssize_t LDB_filter_list_store(struct kobject *kobj, struct kobj_attribute *attr,
				 const char *buf, size_t count) {
	char *temp_buf = kmalloc(count + 1, GFP_KERNEL);
	if (!temp_buf)
		return -ENOMEM;
	strncpy(temp_buf, buf, count);
	temp_buf[count] = '\0'; // Ensure null-termination

	size_t i;
	char *line, *cur = temp_buf;
	size_t len;

	// Free existing entries
	for (i = 0; i < LDB_MAX_FILE_NUM; i++) {
		kfree(LDB_filter_list[i]);
		LDB_filter_list[i] = NULL;
	}
	// read config file, each line a string
	i = 0;
	while ((line = strsep(&cur, "\n")) && i < LDB_MAX_FILE_NUM) {
		if (*line == '\0') // Skip empty lines
			continue;
		len = strlen(line);
		if (len > 0) {
			LDB_filter_list[i] = kstrndup(line, len, GFP_KERNEL);
			if (!LDB_filter_list[i])
				return -ENOMEM; // Failed to allocate memory for the string
			i++;
			printk(KERN_INFO "[MY] LDB_filter_list_store %d : %s\n", i, line);
		}
	}

	kfree(temp_buf);

	return count;
}
static void LDB_filter_list_release(struct kobject *kobj)
{
	// Invoked when kobject_put is called to destroy this kobject
	// Free existing entries
	size_t i;
	for (i = 0; i < LDB_MAX_FILE_NUM; i++) {
		kfree(LDB_filter_list[i]);
		LDB_filter_list[i] = NULL;
	}
	printk(KERN_INFO "[MY] LDB_filter_list_release\n");
}

//// Defines the sysfs operation methods (read and write).
//struct sysfs_ops my_sysfs_ops = {
//	.show = LDB_filter_list_show,
//	.store = LDB_filter_list_store,
//};

// define attribute "filter_list"
static struct kobj_attribute LDB_filter_list_attribute =
	__ATTR(filter_list, 0644, LDB_filter_list_show, LDB_filter_list_store);// name, mode, show, store
static struct attribute *LDB_filter_list_attrs[] = {
	&LDB_filter_list_attribute.attr,
	NULL,
};
// same to ATTRIBUTE_GROUPS(LDB_filter_list);
static const struct attribute_group LDB_filter_list_group = {
	.attrs = LDB_filter_list_attrs,
};
static const struct attribute_group *LDB_filter_list_groups[] = {
	&LDB_filter_list_group,
	((void *)0),
};

/*
 * Our own ktype for our kobjects.  Here we specify our sysfs ops, the
 * release function, and the set of attributes we want created
 * whenever a kobject of this type is registered with the kernel.
 */
static struct kobj_type LDB_filter_list_ktype = {
//	.sysfs_ops = &my_sysfs_ops,
	.sysfs_ops = &kobj_sysfs_ops,
	.release = LDB_filter_list_release,
	.default_groups = LDB_filter_list_groups,
};


//== add code end




static void nfs_netns_object_release(struct kobject *kobj)
{
	kfree(kobj);
}

static const struct kobj_ns_type_operations *nfs_netns_object_child_ns_type(
		struct kobject *kobj)
{
	return &net_ns_type_operations;
}

static struct kobj_type nfs_netns_object_type = {
	.release = nfs_netns_object_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.child_ns_type = nfs_netns_object_child_ns_type,
};

static struct kobject *nfs_netns_object_alloc(const char *name,
		struct kset *kset, struct kobject *parent)
{
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (kobj) {
		kobj->kset = kset;
		if (kobject_init_and_add(kobj, &nfs_netns_object_type,
					parent, "%s", name) == 0)
			return kobj;
		kobject_put(kobj);
	}
	return NULL;
}
//== add code
static struct kobject *nfs_filter_object_alloc(const char *name,
					      struct kset *kset, struct kobject *parent)
{
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (kobj) {
		kobj->kset = kset;
		if (kobject_init_and_add(kobj, &LDB_filter_list_ktype,
					 parent, "%s", name) == 0)
			return kobj;
		kobject_put(kobj);
	}
	return NULL;
}

int nfs_sysfs_init(void)
{
	nfs_client_kset = kset_create_and_add("nfs", NULL, fs_kobj);
	if (!nfs_client_kset)
		return -ENOMEM;
	nfs_client_kobj = nfs_netns_object_alloc("net", nfs_client_kset, NULL);
	if  (!nfs_client_kobj) {
		kset_unregister(nfs_client_kset);
		nfs_client_kset = NULL;
		return -ENOMEM;
	}

	//== add code
	/*
	  * Create a simple kobject with the name of "nfs_filter",
	  * located under /sys/fs/nfs/
	  * The kobject path will be: /sys/fs/nfs/nfs_filter
	  */
	nfs_filter_kobj = nfs_filter_object_alloc("nfs_filter", nfs_client_kset, NULL);
	if(!nfs_filter_kobj){
		kset_unregister(nfs_client_kset);
		nfs_client_kset = NULL;
		return -ENOMEM;
	}
	printk(KERN_INFO "[MY] nfs_sysfs_init create nfs_filter kobj\n");

	return 0;
}

void nfs_sysfs_exit(void)
{
	kobject_put(nfs_client_kobj);
	//== add code
	kobject_put(nfs_filter_kobj);
	kset_unregister(nfs_client_kset);
}

static ssize_t nfs_netns_identifier_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			kobject);
	ssize_t ret;

	rcu_read_lock();
	ret = scnprintf(buf, PAGE_SIZE, "%s\n", rcu_dereference(c->identifier));
	rcu_read_unlock();
	return ret;
}

/* Strip trailing '\n' */
static size_t nfs_string_strip(const char *c, size_t len)
{
	while (len > 0 && c[len-1] == '\n')
		--len;
	return len;
}

static ssize_t nfs_netns_identifier_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			kobject);
	const char *old;
	char *p;
	size_t len;

	len = nfs_string_strip(buf, min_t(size_t, count, CONTAINER_ID_MAXLEN));
	if (!len)
		return 0;
	p = kmemdup_nul(buf, len, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	old = rcu_dereference_protected(xchg(&c->identifier, (char __rcu *)p), 1);
	if (old) {
		synchronize_rcu();
		kfree(old);
	}
	return count;
}

static void nfs_netns_client_release(struct kobject *kobj)
{
	struct nfs_netns_client *c = container_of(kobj,
			struct nfs_netns_client,
			kobject);

	kfree(rcu_dereference_raw(c->identifier));
	kfree(c);
}

static const void *nfs_netns_client_namespace(struct kobject *kobj)
{
	return container_of(kobj, struct nfs_netns_client, kobject)->net;
}

static struct kobj_attribute nfs_netns_client_id = __ATTR(identifier,
		0644, nfs_netns_identifier_show, nfs_netns_identifier_store);

static struct attribute *nfs_netns_client_attrs[] = {
	&nfs_netns_client_id.attr,
	NULL,
};

static struct kobj_type nfs_netns_client_type = {
	.release = nfs_netns_client_release,
	.default_attrs = nfs_netns_client_attrs,
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = nfs_netns_client_namespace,
};

static struct nfs_netns_client *nfs_netns_client_alloc(struct kobject *parent,
		struct net *net)
{
	struct nfs_netns_client *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p) {
		p->net = net;
		p->kobject.kset = nfs_client_kset;
		if (kobject_init_and_add(&p->kobject, &nfs_netns_client_type,
					parent, "nfs_client") == 0)
			return p;
		kobject_put(&p->kobject);
	}
	return NULL;
}

void nfs_netns_sysfs_setup(struct nfs_net *netns, struct net *net)
{
	struct nfs_netns_client *clp;

	clp = nfs_netns_client_alloc(nfs_client_kobj, net);
	if (clp) {
		netns->nfs_client = clp;
		kobject_uevent(&clp->kobject, KOBJ_ADD);
	}
}

void nfs_netns_sysfs_destroy(struct nfs_net *netns)
{
	struct nfs_netns_client *clp = netns->nfs_client;

	if (clp) {
		kobject_uevent(&clp->kobject, KOBJ_REMOVE);
		kobject_del(&clp->kobject);
		kobject_put(&clp->kobject);
		netns->nfs_client = NULL;
	}
}