/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 */

#define KMSG_COMPONENT "zram"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/lzo.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "zram_drv.h"

/* Globals */
static int zram_major;
struct zram *zram_devices;

/* Module params (documentation at end) */
static unsigned int num_devices;

static void zram_stat_inc(u32 *v)
{
	*v = *v + 1;
}

static void zram_stat_dec(u32 *v)
{
	*v = *v - 1;
}

static void zram_stat64_add(struct zram *zram, u64 *v, u64 inc)
{
	spin_lock(&zram->stat64_lock);
	*v = *v + inc;
	spin_unlock(&zram->stat64_lock);
}

static void zram_stat64_sub(struct zram *zram, u64 *v, u64 dec)
{
	spin_lock(&zram->stat64_lock);
	*v = *v - dec;
	spin_unlock(&zram->stat64_lock);
}

static void zram_stat64_inc(struct zram *zram, u64 *v)
{
	zram_stat64_add(zram, v, 1);
}

static int zram_test_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	return zram->table[index].flags & BIT(flag);
}

static void zram_set_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags |= BIT(flag);
}

static void zram_clear_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags &= ~BIT(flag);
}

static int page_zero_filled(void *ptr)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

static void zram_set_disksize(struct zram *zram, size_t totalram_bytes)
{
	if (!zram->disksize) {
		pr_info(
		"disk size not provided. You can use disksize_kb module "
		"param to specify size.\nUsing default: (%u%% of RAM).\n",
		default_disksize_perc_ram
		);
		zram->disksize = default_disksize_perc_ram *
					(totalram_bytes / 100);
	}

	if (zram->disksize > 2 * (totalram_bytes)) {
		pr_info(
		"There is little point creating a zram of greater than "
		"twice the size of memory since we expect a 2:1 compression "
		"ratio. Note that zram uses about 0.1%% of the size of "
		"the disk when not in use so a huge zram is "
		"wasteful.\n"
		"\tMemory Size: %zu kB\n"
		"\tSize you selected: %llu kB\n"
		"Continuing anyway ...\n",
		totalram_bytes >> 10, zram->disksize
		);
	}

	zram->disksize &= PAGE_MASK;
}

static void zram_free_page(struct zram *zram, size_t index)
{
	void *handle = zram->table[index].handle;

	if (unlikely(!handle)) {
		/*
		 * No memory is allocated for zero filled pages.
		 * Simply clear zero page flag.
		 */
		if (zram_test_flag(zram, index, ZRAM_ZERO)) {
			zram_clear_flag(zram, index, ZRAM_ZERO);
			zram_stat_dec(&zram->stats.pages_zero);
		}
		return;
	}

	if (unlikely(zram_test_flag(zram, index, ZRAM_UNCOMPRESSED))) {
		__free_page(handle);
		zram_clear_flag(zram, index, ZRAM_UNCOMPRESSED);
		zram_stat_dec(&zram->stats.pages_expand);
		goto out;
	}

	zs_free(zram->mem_pool, handle);

	if (zram->table[index].size <= PAGE_SIZE / 2)
		zram_stat_dec(&zram->stats.good_compress);

out:
	zram_stat64_sub(zram, &zram->stats.compr_size,
			zram->table[index].size);
	zram_stat_dec(&zram->stats.pages_stored);

	zram->table[index].handle = NULL;
	zram->table[index].size = 0;
}

static void handle_zero_page(struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	void *user_mem;

	user_mem = kmap_atomic(page);
	memset(user_mem + bvec->bv_offset, 0, bvec->bv_len);
	kunmap_atomic(user_mem);

	flush_dcache_page(page);
}

static void handle_uncompressed_page(struct zram *zram, struct bio_vec *bvec,
				     u32 index, int offset)
{
	struct page *page = bvec->bv_page;
	unsigned char *user_mem, *cmem;

	user_mem = kmap_atomic(page);
	cmem = kmap_atomic(zram->table[index].handle);

	memcpy(user_mem + bvec->bv_offset, cmem + offset, bvec->bv_len);
	kunmap_atomic(cmem);
	kunmap_atomic(user_mem);

	flush_dcache_page(page);
}

static inline bool is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}

static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
			  u32 index, int offset)
{
	int ret;
	size_t clen;
	struct page *page;
	struct zobj_header *zheader;
	unsigned char *user_mem, *cmem, *uncmem = NULL;

	page = bvec->bv_page;

	if (zram_test_flag(zram, index, ZRAM_ZERO)) {
		handle_zero_page(bvec);
		return 0;
	}

	/* Requested page is not present in compressed area */
	if (unlikely(!zram->table[index].handle)) {
		pr_debug("Read before write: sector=%lu, size=%u",
			 (ulong)(bio->bi_sector), bio->bi_size);
		handle_zero_page(bvec);
		return 0;
	}

	/* Page is stored uncompressed since it's incompressible */
	if (unlikely(zram_test_flag(zram, index, ZRAM_UNCOMPRESSED))) {
		handle_uncompressed_page(zram, bvec, index, offset);
		return 0;
	}

	if (is_partial_io(bvec)) {
		/* Use  a temporary buffer to decompress the page */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);
		if (!uncmem) {
			pr_info("Error allocating temp memory!\n");
			return -ENOMEM;
		}
	}

	user_mem = kmap_atomic(page);
	if (!is_partial_io(bvec))
		uncmem = user_mem;
	clen = PAGE_SIZE;

	cmem = zs_map_object(zram->mem_pool, zram->table[index].handle);

	ret = lzo1x_decompress_safe(cmem + sizeof(*zheader),
				    zram->table[index].size,
				    uncmem, &clen);

	if (is_partial_io(bvec)) {
		memcpy(user_mem + bvec->bv_offset, uncmem + offset,
		       bvec->bv_len);
		kfree(uncmem);
	}

	zs_unmap_object(zram->mem_pool, zram->table[index].handle);
	kunmap_atomic(user_mem);

	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret != LZO_E_OK)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
		zram_stat64_inc(zram, &zram->stats.failed_reads);
		return ret;
	}

	flush_dcache_page(page);

	return 0;
}

static int zram_read_before_write(struct zram *zram, char *mem, u32 index)
{
	int ret;
	size_t clen = PAGE_SIZE;
	struct zobj_header *zheader;
	unsigned char *cmem;

	if (zram_test_flag(zram, index, ZRAM_ZERO) ||
	    !zram->table[index].handle) {
		memset(mem, 0, PAGE_SIZE);
		return 0;
	}

	cmem = zs_map_object(zram->mem_pool, zram->table[index].handle);

	/* Page is stored uncompressed since it's incompressible */
	if (unlikely(zram_test_flag(zram, index, ZRAM_UNCOMPRESSED))) {
		memcpy(mem, cmem, PAGE_SIZE);
		kunmap_atomic(cmem);
		return 0;
	}

	ret = lzo1x_decompress_safe(cmem + sizeof(*zheader),
				    zram->table[index].size,
				    mem, &clen);
	zs_unmap_object(zram->mem_pool, zram->table[index].handle);

	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret != LZO_E_OK)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
		zram_stat64_inc(zram, &zram->stats.failed_reads);
		return ret;
	}

	return 0;
}

static int zram_bvec_write(struct zram *zram, struct bio_vec *bvec, u32 index,
			   int offset)
{
	int ret;
	u32 store_offset;
	size_t clen;
	void *handle;
	struct zobj_header *zheader;
	struct page *page, *page_store;
	unsigned char *user_mem, *cmem, *src, *uncmem = NULL;

	page = bvec->bv_page;
	src = zram->compress_buffer;

	if (is_partial_io(bvec)) {
		/*
		 * This is a partial IO. We need to read the full page
		 * before to write the changes.
		 */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);
		if (!uncmem) {
			pr_info("Error allocating temp memory!\n");
			ret = -ENOMEM;
			goto out;
		}
		ret = zram_read_before_write(zram, uncmem, index);
		if (ret) {
			kfree(uncmem);
			goto out;
		}
	}

	/*
	 * System overwrites unused sectors. Free memory associated
	 * with this sector now.
	 */
	if (zram->table[index].handle ||
	    zram_test_flag(zram, index, ZRAM_ZERO))
		zram_free_page(zram, index);

	zstrm = zcomp_strm_find(zram->comp);
	user_mem = kmap_atomic(page);

	if (is_partial_io(bvec))
		memcpy(uncmem + offset, user_mem + bvec->bv_offset,
		       bvec->bv_len);
	else
		uncmem = user_mem;

	if (page_zero_filled(uncmem)) {
		kunmap_atomic(user_mem);
		if (is_partial_io(bvec))
			kfree(uncmem);
		zram_stat_inc(&zram->stats.pages_zero);
		zram_set_flag(zram, index, ZRAM_ZERO);
		ret = 0;
		goto out;
	}

	ret = lzo1x_1_compress(uncmem, PAGE_SIZE, src, &clen,
			       zram->compress_workmem);

	kunmap_atomic(user_mem);
	if (is_partial_io(bvec))
			kfree(uncmem);

	if (unlikely(ret != LZO_E_OK)) {
		pr_err("Compression failed! err=%d\n", ret);
		goto out;
	}

	/*
	 * Page is incompressible. Store it as-is (uncompressed)
	 * since we do not want to return too many disk write
	 * errors which has side effect of hanging the system.
	 */
	if (unlikely(clen > max_zpage_size)) {
		clen = PAGE_SIZE;
		page_store = alloc_page(GFP_NOIO | __GFP_HIGHMEM);
		if (unlikely(!page_store)) {
			pr_info("Error allocating memory for "
				"incompressible page: %u\n", index);
			ret = -ENOMEM;
			goto out;
		}

		store_offset = 0;
		zram_set_flag(zram, index, ZRAM_UNCOMPRESSED);
		zram_stat_inc(&zram->stats.pages_expand);
		handle = page_store;
		src = kmap_atomic(page);
		cmem = kmap_atomic(page_store);
		goto memstore;
	}

	handle = zs_malloc(zram->mem_pool, clen + sizeof(*zheader));
	if (!handle) {
		pr_err("Error allocating memory for compressed page: %u, size=%zu\n",
			index, clen);
		ret = -ENOMEM;
		goto out;
	}
	cmem = zs_map_object(zram->mem_pool, handle);

memstore:
#if 0
	/* Back-reference needed for memory defragmentation */
	if (!zram_test_flag(zram, index, ZRAM_UNCOMPRESSED)) {
		zheader = (struct zobj_header *)cmem;
		zheader->table_idx = index;
		cmem += sizeof(*zheader);
	}
#endif

	memcpy(cmem, src, clen);

	if (unlikely(zram_test_flag(zram, index, ZRAM_UNCOMPRESSED))) {
		kunmap_atomic(cmem);
		kunmap_atomic(src);
	} else {
		zs_unmap_object(zram->mem_pool, handle);
	}

	zram->table[index].handle = handle;
	zram->table[index].size = clen;

	/* Update stats */
	zram_stat64_add(zram, &zram->stats.compr_size, clen);
	zram_stat_inc(&zram->stats.pages_stored);
	if (clen <= PAGE_SIZE / 2)
		zram_stat_inc(&zram->stats.good_compress);

	return 0;

out:
	if (ret)
		zram_stat64_inc(zram, &zram->stats.failed_writes);
	return ret;
}

static int zram_bvec_rw(struct zram *zram, struct bio_vec *bvec, u32 index,
			int offset, struct bio *bio, int rw)
{
	int ret;

	if (rw == READ) {
		down_read(&zram->lock);
		ret = zram_bvec_read(zram, bvec, index, offset, bio);
		up_read(&zram->lock);
	} else {
		down_write(&zram->lock);
		ret = zram_bvec_write(zram, bvec, index, offset);
		up_write(&zram->lock);
	}

	if (unlikely(ret)) {
		if (rw == READ)
			atomic64_inc(&zram->stats.failed_reads);
		else
			atomic64_inc(&zram->stats.failed_writes);
	}

	return ret;
}

static inline bool zram_meta_get(struct zram *zram)
{
	if (atomic_inc_not_zero(&zram->refcount))
		return true;
	return false;
}

static inline void zram_meta_put(struct zram *zram)
{
	atomic_dec(&zram->refcount);
}

static void update_position(u32 *index, int *offset, struct bio_vec *bvec)
{
	if (*offset + bvec->bv_len >= PAGE_SIZE)
		(*index)++;
	*offset = (*offset + bvec->bv_len) % PAGE_SIZE;
}

static void __zram_make_request(struct zram *zram, struct bio *bio, int rw)
{
	int offset, rw, i;
	u32 index;
	struct bio_vec *bvec;

	switch (rw) {
	case READ:
		zram_stat64_inc(zram, &zram->stats.num_reads);
		break;
	case WRITE:
		zram_stat64_inc(zram, &zram->stats.num_writes);
		break;
	}

	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (bio->bi_sector &
		  (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	rw = bio_data_dir(bio);
	bio_for_each_segment(bvec, bio, i) {
		int max_transfer_size = PAGE_SIZE - offset;

		if (bvec->bv_len > max_transfer_size) {
			/*
			 * zram_bvec_rw() can only make operation on a single
			 * zram page. Split the bio vector.
			 */
			struct bio_vec bv;

			bv.bv_page = bvec->bv_page;
			bv.bv_len = max_transfer_size;
			bv.bv_offset = bvec->bv_offset;

			if (zram_bvec_rw(zram, &bv, index, offset, rw) < 0)
				goto out;

			bv.bv_len = bvec->bv_len - max_transfer_size;
			bv.bv_offset += max_transfer_size;
			if (zram_bvec_rw(zram, &bv, index + 1, 0, rw) < 0)
				goto out;
		} else
			if (zram_bvec_rw(zram, bvec, index, offset, rw) < 0)
				goto out;

		update_position(&index, &offset, bvec);
	}

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return;

out:
	bio_io_error(bio);
}

/*
 * Check if request is within bounds and aligned on zram logical blocks.
 */
static inline bool valid_io_request(struct zram *zram,
		sector_t start, unsigned int size)
{
	u64 end, bound;

	/* unaligned request */
	if (unlikely(start & (ZRAM_SECTOR_PER_LOGICAL_BLOCK - 1)))
		return false;
	if (unlikely(size & (ZRAM_LOGICAL_BLOCK_SIZE - 1)))
		return false;

	end = start + (size >> SECTOR_SHIFT);
	bound = zram->disksize >> SECTOR_SHIFT;
	/* out of range range */
	if (unlikely(start >= bound || end > bound || start > end))
		return false;

	/* I/O request is valid */
	return true;
}

/*
 * Handler function for all zram I/O requests.
 */
static void zram_make_request(struct request_queue *queue, struct bio *bio)
{
	struct zram *zram = queue->queuedata;

	if (unlikely(!zram->init_done) && zram_init_device(zram))
		goto error;

	deprecated_attr_warn("mem_used_total");
	down_read(&zram->init_lock);
	if (unlikely(!zram->init_done))
		goto error_unlock;

	if (!valid_io_request(zram, bio)) {
		zram_stat64_inc(zram, &zram->stats.invalid_io);
		goto error_unlock;
	}

	__zram_make_request(zram, bio);
	up_read(&zram->init_lock);

	return;

error_unlock:
	up_read(&zram->init_lock);
error:
	bio_io_error(bio);
}

void __zram_reset_device(struct zram *zram)
{
	size_t index;

	zram->init_done = 0;

	/* Free various per-device buffers */
	kfree(zram->compress_workmem);
	free_pages((unsigned long)zram->compress_buffer, 1);

	zram->compress_workmem = NULL;
	zram->compress_buffer = NULL;

	/* Free all pages that are still in this zram device */
	for (index = 0; index < zram->disksize >> PAGE_SHIFT; index++) {
		void *handle = zram->table[index].handle;
		if (!handle)
			continue;

		if (unlikely(zram_test_flag(zram, index, ZRAM_UNCOMPRESSED)))
			__free_page(handle);
		else
			zs_free(zram->mem_pool, handle);
	}

	vfree(zram->table);
	zram->table = NULL;

	zs_destroy_pool(zram->mem_pool);
	zram->mem_pool = NULL;

	/* Reset stats */
	memset(&zram->stats, 0, sizeof(zram->stats));

	zram->disksize = 0;
}

void zram_reset_device(struct zram *zram)
{
	struct zram_meta *meta;
	struct zcomp *comp;
	u64 disksize;

	if (!zcomp_available_algorithm(buf))
		return -EINVAL;

	down_write(&zram->init_lock);
	__zram_reset_device(zram);
	up_write(&zram->init_lock);
}

int zram_init_device(struct zram *zram)
{
	int ret;
	size_t num_pages;

	down_write(&zram->init_lock);

	if (zram->init_done) {
		up_write(&zram->init_lock);
		return 0;
	}

	zram_set_disksize(zram, totalram_pages << PAGE_SHIFT);

	zram->compress_workmem = kzalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
	if (!zram->compress_workmem) {
		pr_err("Error allocating compressor working memory!\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	zram->compress_buffer =
		(void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!zram->compress_buffer) {
		pr_err("Error allocating compressor buffer space\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	num_pages = zram->disksize >> PAGE_SHIFT;
	zram->table = vzalloc(num_pages * sizeof(*zram->table));
	if (!zram->table) {
		pr_err("Error allocating zram address table\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	set_capacity(zram->disk, zram->disksize >> SECTOR_SHIFT);

	/* zram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);

	zram->mem_pool = zs_create_pool("zram", GFP_NOIO | __GFP_HIGHMEM);
	if (!zram->mem_pool) {
		pr_err("Error creating memory pool\n");
		ret = -ENOMEM;
		goto fail;
	}

	zram->init_done = 1;
	up_write(&zram->init_lock);

	pr_debug("Initialization done!\n");
	return 0;

fail_no_table:
	/* To prevent accessing table entries during cleanup */
	zram->disksize = 0;
fail:
	__zram_reset_device(zram);
	up_write(&zram->init_lock);
	pr_err("Initialization failed: err=%d\n", ret);
	return ret;
}

static void zram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct zram *zram;

	zram = bdev->bd_disk->private_data;
	zram_free_page(zram, index);
	zram_stat64_inc(zram, &zram->stats.notify_free);
}

/* not ready for this change right now: Dorimanx */
#if 0
static int zram_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, int rw)
{
	int offset, err = -EIO;
	u32 index;
	struct zram *zram;
	struct bio_vec bv;

	zram = bdev->bd_disk->private_data;
	if (unlikely(!zram_meta_get(zram)))
		goto out;

	if (!valid_io_request(zram, sector, PAGE_SIZE)) {
		atomic64_inc(&zram->stats.invalid_io);
		err = -EINVAL;
		goto put_zram;
	}

	index = sector >> SECTORS_PER_PAGE_SHIFT;
	offset = sector & (SECTORS_PER_PAGE - 1) << SECTOR_SHIFT;

	bv.bv_page = page;
	bv.bv_len = PAGE_SIZE;
	bv.bv_offset = 0;

	err = zram_bvec_rw(zram, &bv, index, offset, rw);
put_zram:
	zram_meta_put(zram);
out:
	/*
	 * If I/O fails, just return error(ie, non-zero) without
	 * calling page_endio.
	 * It causes resubmit the I/O with bio request by upper functions
	 * of rw_page(e.g., swap_readpage, __swap_writepage) and
	 * bio->bi_end_io does things to handle the error
	 * (e.g., SetPageError, set_page_dirty and extra works).
	 */
	if (err == 0)
		page_endio(page, rw, 0);
	return err;
}
#endif

static void zram_reset_device(struct zram *zram)
{
	struct zram_meta *meta;
	struct zcomp *comp;
	u64 disksize;

	down_write(&zram->init_lock);

	zram->limit_pages = 0;

	if (!init_done(zram)) {
		up_write(&zram->init_lock);
		return;
	}

	meta = zram->meta;
	comp = zram->comp;
	disksize = zram->disksize;
	/*
	 * Refcount will go down to 0 eventually and r/w handler
	 * cannot handle further I/O so it will bail out by
	 * check zram_meta_get.
	 */
	zram_meta_put(zram);
	/*
	 * We want to free zram_meta in process context to avoid
	 * deadlock between reclaim path and any other locks.
	 */
	wait_event(zram->io_done, atomic_read(&zram->refcount) == 0);

	/* Reset stats */
	memset(&zram->stats, 0, sizeof(zram->stats));
	zram->disksize = 0;

	set_capacity(zram->disk, 0);
	part_stat_set_all(&zram->disk->part0, 0);

	up_write(&zram->init_lock);
	/* I/O operation under all of CPU are done so let's free */
	zram_meta_free(meta, disksize);
	zcomp_destroy(comp);
}

static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct zcomp *comp;
	struct zram_meta *meta;
	struct zram *zram = dev_to_zram(dev);
	int err;

	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	disksize = PAGE_ALIGN(disksize);
	meta = zram_meta_alloc(zram->disk->disk_name, disksize);
	if (!meta)
		return -ENOMEM;

	comp = zcomp_create(zram->compressor);
	if (IS_ERR(comp)) {
		pr_err("Cannot initialise %s compressing backend\n",
				zram->compressor);
		err = PTR_ERR(comp);
		goto out_free_meta;
	}

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Cannot change disksize for initialized device\n");
		err = -EBUSY;
		goto out_destroy_comp;
	}

	init_waitqueue_head(&zram->io_done);
	atomic_set(&zram->refcount, 1);
	zram->meta = meta;
	zram->comp = comp;
	zram->disksize = disksize;
	set_capacity(zram->disk, zram->disksize >> SECTOR_SHIFT);
	up_write(&zram->init_lock);

	/*
	 * Revalidate disk out of the init_lock to avoid lockdep splat.
	 * It's okay because disk's capacity is protected by init_lock
	 * so that revalidate_disk always sees up-to-date capacity.
	 */
	revalidate_disk(zram->disk);

	return len;

out_destroy_comp:
	up_write(&zram->init_lock);
	zcomp_destroy(comp);
out_free_meta:
	zram_meta_free(meta, disksize);
	return err;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned short do_reset;
	struct zram *zram;
	struct block_device *bdev;

	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		return ret;

	if (!do_reset)
		return -EINVAL;

	zram = dev_to_zram(dev);
	bdev = bdget_disk(zram->disk, 0);
	if (!bdev)
		return -ENOMEM;

	mutex_lock(&bdev->bd_mutex);
	/* Do not reset an active device or claimed device */
	if (bdev->bd_openers || zram->claim) {
		mutex_unlock(&bdev->bd_mutex);
		bdput(bdev);
		return -EBUSY;
	}

	/* From now on, anyone can't open /dev/zram[0-9] */
	zram->claim = true;
	mutex_unlock(&bdev->bd_mutex);

	/* Make sure all the pending I/O are finished */
	fsync_bdev(bdev);
	zram_reset_device(zram);
	revalidate_disk(zram->disk);
	bdput(bdev);

	mutex_lock(&bdev->bd_mutex);
	zram->claim = false;
	mutex_unlock(&bdev->bd_mutex);

	return len;
}

static int zram_open(struct block_device *bdev, fmode_t mode)
{
	int ret = 0;
	struct zram *zram;

	WARN_ON(!mutex_is_locked(&bdev->bd_mutex));

	zram = bdev->bd_disk->private_data;
	/* zram was claimed to reset so open request fails */
	if (zram->claim)
		ret = -EBUSY;

	return ret;
}

static const struct block_device_operations zram_devops = {
	.open = zram_open,
	.swap_slot_free_notify = zram_slot_free_notify,
#if 0
	.rw_page = zram_rw_page,
#endif
	.owner = THIS_MODULE
};

static int create_device(struct zram *zram, int device_id)
{
	int ret = -ENOMEM;

	init_rwsem(&zram->lock);
	init_rwsem(&zram->init_lock);
	spin_lock_init(&zram->stat64_lock);

	zram->queue = blk_alloc_queue(GFP_KERNEL);
	if (!zram->queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
		goto out;
	}

	blk_queue_make_request(zram->queue, zram_make_request);
	zram->queue->queuedata = zram;

	 /* gendisk structure */
	zram->disk = alloc_disk(1);
	if (!zram->disk) {
		pr_warning("Error allocating disk structure for device %d\n",
			device_id);
		ret = -ENOMEM;
		goto out_free_queue;
	}

	zram->disk->major = zram_major;
	zram->disk->first_minor = device_id;
	zram->disk->fops = &zram_devops;
	zram->disk->queue = queue;
	zram->disk->queue->queuedata = zram;
	zram->disk->private_data = zram;
	snprintf(zram->disk->disk_name, 16, "zram%d", device_id);

	__set_bit(QUEUE_FLAG_FAST, &zram->disk->queue->queue_flags);
	/* Actual capacity set using syfs (/sys/block/zram<id>/disksize */
	set_capacity(zram->disk, 0);
	/* zram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, zram->disk->queue);
	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(zram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(zram->disk->queue,
					ZRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(zram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(zram->disk->queue, PAGE_SIZE);
	zram->disk->queue->limits.discard_granularity = PAGE_SIZE;
	blk_queue_max_discard_sectors(zram->disk->queue, UINT_MAX);
	/*
	 * zram_bio_discard() will clear all logical blocks if logical block
	 * size is identical with physical block size(PAGE_SIZE). But if it is
	 * different, we will skip discarding some parts of logical blocks in
	 * the part of the request range which isn't aligned to physical block
	 * size.  So we can't ensure that all discarded logical blocks are
	 * zeroed.
	 */
	if (ZRAM_LOGICAL_BLOCK_SIZE == PAGE_SIZE)
		zram->disk->queue->limits.discard_zeroes_data = 1;
	else
		zram->disk->queue->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, zram->disk->queue);

	add_disk(zram->disk);

	ret = sysfs_create_group(&disk_to_dev(zram->disk)->kobj,
				&zram_disk_attr_group);
	if (ret < 0) {
		pr_warning("Error creating sysfs group");
		goto out_free_disk;
	}
	strlcpy(zram->compressor, default_compressor, sizeof(zram->compressor));
	zram->meta = NULL;

	pr_info("Added device: %s\n", zram->disk->disk_name);
	return device_id;

out_free_disk:
	del_gendisk(zram->disk);
	put_disk(zram->disk);
out_free_queue:
	blk_cleanup_queue(queue);
out_free_idr:
	idr_remove(&zram_index_idr, device_id);
out_free_dev:
	kfree(zram);
	return ret;
}

static int zram_remove(struct zram *zram)
{
	struct block_device *bdev;

	bdev = bdget_disk(zram->disk, 0);
	if (!bdev)
		return -ENOMEM;

	mutex_lock(&bdev->bd_mutex);
	if (bdev->bd_openers || zram->claim) {
		mutex_unlock(&bdev->bd_mutex);
		bdput(bdev);
		return -EBUSY;
	}

	zram->claim = true;
	mutex_unlock(&bdev->bd_mutex);

	/*
	 * Remove sysfs first, so no one will perform a disksize
	 * store while we destroy the devices. This also helps during
	 * hot_remove -- zram_reset_device() is the last holder of
	 * ->init_lock, no later/concurrent disksize_store() or any
	 * other sysfs handlers are possible.
	 */
	sysfs_remove_group(&disk_to_dev(zram->disk)->kobj,
			&zram_disk_attr_group);

	/* Make sure all the pending I/O are finished */
	fsync_bdev(bdev);
	zram_reset_device(zram);
	bdput(bdev);

	pr_info("Removed device: %s\n", zram->disk->disk_name);

	blk_cleanup_queue(zram->disk->queue);
	del_gendisk(zram->disk);
	put_disk(zram->disk);
	kfree(zram);
	return 0;
}

/* zram-control sysfs attributes */
static ssize_t hot_add_show(struct class *class,
			struct class_attribute *attr,
			char *buf)
{
	int ret;

	mutex_lock(&zram_index_mutex);
	ret = zram_add();
	mutex_unlock(&zram_index_mutex);

	if (ret < 0)
		return ret;
	return scnprintf(buf, PAGE_SIZE, "%d\n", ret);
}

static ssize_t hot_remove_store(struct class *class,
			struct class_attribute *attr,
			const char *buf,
			size_t count)
{
	struct zram *zram;
	int ret, dev_id;

	/* dev_id is gendisk->first_minor, which is `int' */
	ret = kstrtoint(buf, 10, &dev_id);
	if (ret)
		return ret;
	if (dev_id < 0)
		return -EINVAL;

	mutex_lock(&zram_index_mutex);

	zram = idr_find(&zram_index_idr, dev_id);
	if (zram) {
		ret = zram_remove(zram);
		idr_remove(&zram_index_idr, dev_id);
	} else {
		ret = -ENODEV;
	}

	mutex_unlock(&zram_index_mutex);
	return ret ? ret : count;
}

static struct class_attribute zram_control_class_attrs[] = {
	__ATTR_RO(hot_add),
	__ATTR_WO(hot_remove),
	__ATTR_NULL,
};

static struct class zram_control_class = {
	.name		= "zram-control",
	.owner		= THIS_MODULE,
	.class_attrs	= zram_control_class_attrs,
};

static int zram_remove_cb(int id, void *ptr, void *data)
{
	zram_remove(ptr);
	return 0;
}

static void destroy_devices(void)
{
	class_unregister(&zram_control_class);
	idr_for_each(&zram_index_idr, &zram_remove_cb, NULL);
	idr_destroy(&zram_index_idr);
	unregister_blkdev(zram_major, "zram");
}

unsigned int zram_get_num_devices(void)
{
	return num_devices;
}

static int __init zram_init(void)
{
	int ret;

	if (num_devices > max_num_devices) {
		pr_warning("Invalid value for num_devices: %u\n",
				num_devices);
		ret = -EINVAL;
		goto out;
	}

	zram_major = register_blkdev(0, "zram");
	if (zram_major <= 0) {
		pr_warning("Unable to get major number\n");
		ret = -EBUSY;
		goto out;
	}

	if (!num_devices) {
		pr_info("num_devices not specified. Using default: 1\n");
		num_devices = 1;
	}

	/* Allocate the device array and initialize each one */
	pr_info("Creating %u devices ...\n", num_devices);
	zram_devices = kzalloc(num_devices * sizeof(struct zram), GFP_KERNEL);
	if (!zram_devices) {
		ret = -ENOMEM;
		goto unregister;
	}

	for (dev_id = 0; dev_id < num_devices; dev_id++) {
		ret = create_device(&zram_devices[dev_id], dev_id);
		if (ret)
			goto free_devices;
	}

	return 0;

free_devices:
	while (dev_id)
		destroy_device(&zram_devices[--dev_id]);
	kfree(zram_devices);
unregister:
	unregister_blkdev(zram_major, "zram");
out:
	return ret;
}

static void __exit zram_exit(void)
{
	int i;
	struct zram *zram;

	for (i = 0; i < num_devices; i++) {
		zram = &zram_devices[i];

		get_disk(zram->disk);
		destroy_device(zram);
		if (zram->init_done)
			zram_reset_device(zram);
		put_disk(zram->disk);
	}

	unregister_blkdev(zram_major, "zram");

	kfree(zram_devices);
	pr_debug("Cleanup done!\n");
}

module_param(num_devices, uint, 0);
MODULE_PARM_DESC(num_devices, "Number of pre-created zram devices");

module_init(zram_init);
module_exit(zram_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Block Device");
