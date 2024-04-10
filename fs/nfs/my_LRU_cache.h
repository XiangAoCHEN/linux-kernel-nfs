//
// Created by cxa on 24-4-3.
//

#ifndef KERNEL_MY_LRU_CACHE_H
#define KERNEL_MY_LRU_CACHE_H
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
//#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/idr.h>

struct entry_key{
	unsigned long		i_ino;//inode
	loff_t			ki_pos;// offset
	int  		key;
};

struct entry_value{
	char *data;   // 指向实际数据的指针
	size_t size;
};
struct cache_entry
{
	struct entry_key key;
	struct entry_value* value;
	size_t freq;
	rwlock_t entry_lock;
	struct list_head list;
};
static DEFINE_MUTEX(cache_lock);
static int init_flag = 0;
static LIST_HEAD(LRU_List_Head);
static LIST_HEAD(free_List_Head);

#define MAX_CACHE_CAPACITY 10 // each entry 4kb, max size 2GB = 524288 * 4KB
static unsigned int cache_size = 5;
static struct idr map;// mapping from a unique id (UID) to a pointer
static int ids[MAX_CACHE_CAPACITY];
static struct entry_key global_keys[MAX_CACHE_CAPACITY];
static struct cache_entry *entries;

int init_cache(void){
	mutex_init(&cache_lock);
	mutex_lock(&cache_lock);// avoid twice init
	if(init_flag==1){
		mutex_unlock(&cache_lock);
		return 0;
	}

	// init map
	idr_init(&map); //initialize idr

	// pre-allocate
	entries = kmalloc(MAX_CACHE_CAPACITY * sizeof(struct cache_entry), GFP_KERNEL);//entry array
	for(size_t i = 0;i< MAX_CACHE_CAPACITY; ++i){
		struct entry_value *value = kmalloc(sizeof(struct entry_value), GFP_KERNEL);
		if (!value){
			kfree(value);
			return -1;
		}
		value->size = PAGE_SIZE;
		value->data = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if(!value->data){
			kfree(value->data);
			return -1;
		}

		entries[i].value = value;
		entries[i].key.key = -1;
		entries[i].freq = 0;
		rwlock_init(&entries[i].entry_lock);// lock

		// add to freelist
		INIT_LIST_HEAD(&entries[i].list);
		list_add(&entries[i].list, &free_List_Head);
	}

	init_flag=1;
	mutex_unlock(&cache_lock);
	return 0;
}

int destroy_cache(void){
	mutex_init(&cache_lock);
	mutex_lock(&cache_lock);// avoid twice init
	if(init_flag==0){
		mutex_unlock(&cache_lock);
		return 0;
	}

	for(size_t i = 0;i< MAX_CACHE_CAPACITY; ++i){
		if(!entries[i].value->data){
			kfree(entries[i].value->data);
		}
		if(!entries[i].value){
			kfree(entries[i].value);
		}
		// rwlock_release()
		list_del(&entries[i].list);
	}
	if(!entries)	kfree(entries);

	idr_destroy(&map); //destroy idr

	init_flag = 0;
	mutex_unlock(&cache_lock);
	return 0;
}

// copy data
int extract_data(struct iov_iter *iter, size_t size, char* buf){
	if (!iter || !buf) return -1;
	if(size == 0) return 0;

	// 从iov_iter 复制数据到 value->data
	if (copy_from_iter(buf, size, iter) != size) {
		// 复制数据时发生错误
		return -1;
	}

	return 0;
}

/* Must be holding cache_lock */
static struct cache_entry *__LRU_list_search(struct entry_key key)
{
	struct cache_entry *i;

	list_for_each_entry(i, &LRU_List_Head, list)
		if (i->key.i_ino == key.i_ino && i->key.ki_pos == key.ki_pos) {
			i->freq++;
			return i;
		}
	return NULL;
}
///* Must be holding cache_lock */
//static void __LRU_cache_delete(struct cache_entry *obj)
//{
//	if(!obj) return;
//
//	list_del(&obj->list);
//	// do not need to flush dirty frames
//	cache_size--;
//}
/* Must be holding cache_lock */
static struct cache_entry * __LRU_cache_evict(void)
{
	struct cache_entry *i, *victim = NULL;
	list_for_each_entry(i, &LRU_List_Head, list) {
		if (!victim || i->freq < victim->freq)
			victim = i;
	}
	return victim;
}

///* Must be holding cache_lock */
//static void __LRU_cache_add(struct cache_entry *obj)
//{
//	if(!obj)return;
//
//	list_add(&obj->list, &LRU_List_Head);
//	if (++cache_size > MAX_CACHE_CAPACITY) {
//		struct cache_entry *i, *victim = NULL;
//		list_for_each_entry(i, &LRU_List_Head, list) {
//			if (!victim || i->freq < victim->freq)
//				victim = i;
//		}
//		__LRU_cache_delete(victim);
//	}
//}

// length <= PAGE_SIZE
int my_cache_add(unsigned long i_ino, loff_t offset,struct iov_iter *from, size_t length)
{
	struct cache_entry *obj;
//	struct cache_entry *obj  = (struct cache_entry *)idr_find(&map,ids[key]);

	// search LRU list
	struct cache_entry *i;
	mutex_lock(&cache_lock);
	list_for_each_entry(i, &LRU_List_Head, list)
		if (i->key.i_ino == i_ino && i->key.ki_pos == offset) {
			obj = i;
		}
	mutex_unlock(&cache_lock);

	if(!obj){// none existing key
		if(!list_empty(&free_List_Head)){// select from freelist
			mutex_lock(&cache_lock);
			obj = list_first_entry_or_null(&free_List_Head,struct cache_entry, list);
			list_del(&obj->list);
			list_add(&obj->list, &LRU_List_Head);
			mutex_unlock(&cache_lock);
		}else{// LRU evict
			mutex_lock(&cache_lock);
			obj = __LRU_cache_evict();
			mutex_unlock(&cache_lock);
		}
		// add to hashtable
//		ids[key] = idr_alloc(&map,obj,0 /*start*/, MAX_CACHE_CAPACITY /*end*/, GFP_KERNEL);
	}
	//else{}// existing key, reuse same frame

	obj->key.i_ino = i_ino ;
	obj->key.ki_pos = offset;
//	obj->key.key = key;
	obj->freq = 0;
	obj->value->size = length;
	// 从iov_iter 复制数据到 value->data
	if (copy_from_iter(obj->value->data, length, from) != length) {
		// 复制数据时发生错误
		return -ENOMEM;
	}

	return 0;
}

struct cache_entry * my_cache_lookup(unsigned long i_ino, loff_t offset)
{
	struct cache_entry *i;
	mutex_lock(&cache_lock);
	list_for_each_entry(i, &LRU_List_Head, list)
		if (i->key.i_ino == i_ino && i->key.ki_pos == offset) {
			i->freq++;
			return i;
		}
	mutex_unlock(&cache_lock);

	return i;
}

#endif //KERNEL_MY_LRU_CACHE_H
