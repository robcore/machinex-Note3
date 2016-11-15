/*
 * Copyright (c) 2012-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/msm_ion.h>
#include <mach/msm_smd.h>
#include <mach/ion.h>
#include <mach/iommu_domains.h>
#include <mach/subsystem_notif.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/dma-contiguous.h>
#include <linux/dma-buf.h>
#include <linux/iommu.h>
#include <linux/kref.h>
#include <linux/sort.h>
#include "adsprpc_compat.h"
#include "adsprpc_shared.h"

#ifndef ION_ADSPRPC_HEAP_ID
#define ION_ADSPRPC_HEAP_ID ION_AUDIO_HEAP_ID
#endif /*ION_ADSPRPC_HEAP_ID*/

#define RPC_TIMEOUT	(5 * HZ)
#define RPC_HASH_BITS	5
#define RPC_HASH_SZ	(1 << RPC_HASH_BITS)
#define BALIGN		32
#define NUM_CHANNELS	 1

#define LOCK_MMAP(kernel)\
		do {\
			if (!kernel)\
				down_read(&current->mm->mmap_sem);\
		} while (0)

#define UNLOCK_MMAP(kernel)\
		do {\
			if (!kernel)\
				up_read(&current->mm->mmap_sem);\
		} while (0)


#define IS_CACHE_ALIGNED(x) (((x) & ((L1_CACHE_BYTES)-1)) == 0)

static inline uintptr_t buf_page_start(void *buf)
{
	uintptr_t start = (uintptr_t) buf & PAGE_MASK;
	return start;
}

static inline uintptr_t buf_page_offset(void *buf)
{
	uintptr_t offset = (uintptr_t) buf & (PAGE_SIZE - 1);
	return offset;
}

static inline int buf_num_pages(void *buf, ssize_t len)
{
	uintptr_t start = buf_page_start(buf) >> PAGE_SHIFT;
	uintptr_t end = (((uintptr_t) buf + len - 1) & PAGE_MASK) >> PAGE_SHIFT;
	int nPages = end - start + 1;
	return nPages;
}

static inline uint32_t buf_page_size(uint32_t size)
{
	uint32_t sz = (size + (PAGE_SIZE - 1)) & PAGE_MASK;
	return sz > PAGE_SIZE ? sz : PAGE_SIZE;
}

static inline int buf_get_pages(void *addr, ssize_t sz, int nr_pages,
				int access, struct smq_phy_page *pages,
				int nr_elems, struct smq_phy_page *range)
{
	struct vm_area_struct *vma, *vmaend;
	uintptr_t start = buf_page_start(addr);
	uintptr_t end = buf_page_start((void *)((uintptr_t)addr + sz - 1));
	uint32_t len = nr_pages << PAGE_SHIFT;
	unsigned long pfn, pfnend, paddr;
	int n = -1, err = 0;

	VERIFY(err, 0 != access_ok(access ? VERIFY_WRITE : VERIFY_READ,
					(void __user *)start, len));
	if (err)
		goto bail;
	VERIFY(err, 0 != (vma = find_vma(current->mm, start)));
	if (err)
		goto bail;
	VERIFY(err, 0 != (vmaend = find_vma(current->mm, end)));
	if (err)
		goto bail;
	n = 0;
	if (follow_pfn(vma, start, &pfn))
		goto bail;
	if (follow_pfn(vmaend, end, &pfnend))
		goto bail;
	VERIFY(err, (pfn + nr_pages - 1) == pfnend);
	if (err)
		goto bail;
	VERIFY(err, nr_elems > 0);
	if (err)
		goto bail;
	VERIFY(err, __pfn_to_phys(pfnend) <= UINT_MAX);
	if (err)
		goto bail;
	paddr = __pfn_to_phys(pfn);
	if (range->size && (paddr < range->addr))
		goto bail;
	if (range->size && ((paddr - range->addr + len) > range->size))
		goto bail;
	pages->addr = paddr;
	pages->size = len;
	n++;
 bail:
	return n;
}

struct fastrpc_buf {
	struct ion_handle *handle;
	void *virt;
	ion_phys_addr_t phys;
	ssize_t size;
	int used;
};

struct smq_context_list;

struct overlap {
	uintptr_t start;
	uintptr_t end;
	int raix;
	uintptr_t mstart;
	uintptr_t mend;
	uintptr_t offset;
};


struct smq_invoke_ctx {
	struct hlist_node hn;
	struct completion work;
	int retval;
	int pid;
	int tgid;
	remote_arg_t *pra;
	remote_arg_t *rpra;
	struct fastrpc_buf obuf;
	struct fastrpc_buf *abufs;
	struct fastrpc_device *dev;
	struct fastrpc_apps *apps; 
	int* fds;
	struct ion_handle** handles;
	int nbufs;
	bool smmu;
	uint32_t sc;
	struct overlap *overs;
	struct overlap **overps;
};

struct smq_context_list {
	struct hlist_head pending;
	struct hlist_head interrupted;
	spinlock_t hlock;
};

struct fastrpc_smmu {
	struct iommu_group *group;
	struct iommu_domain *domain;
	int domain_id;
	bool enabled;
};

struct fastrpc_channel_context {
	smd_channel_t *chan;
	struct device *dev;
	struct completion work;
	struct fastrpc_smmu smmu;
	struct kref kref;
	struct notifier_block nb;
	int ssrcount;
	int prevssrcount;
};

struct fastrpc_apps {
	struct fastrpc_chan_ctx channel[NUM_CHANNELS];
	int nchans;
	struct cdev cdev;
	struct class *class;
	struct mutex smd_mutex;
	struct smq_phy_page range;
	struct hlist_head maps;
	dev_t dev_no;
	int compat;
	struct hlist_head drivers;
	spinlock_t hlock;
	int32_t domain_id;
	struct device *adsp_mem_device;
};

struct fastrpc_mmap {
	struct hlist_node hn;
	struct fastrpc_file *fl;
	struct fastrpc_apps *apps;
	int fd;
	uint32_t flags;
	struct dma_buf *buf;
	struct sg_table *table;
	struct dma_buf_attachment *attach;
	uintptr_t phys;
	ssize_t size;
	uintptr_t va;
	ssize_t len;
	int refs;
	uintptr_t raddr;
	struct ion_handle *handle;
	struct ion_client *client;
};

struct fastrpc_channel_info {
	char *name;
	char *node;
	char *group;
	char *subsys;
	int channel;
};

static struct fastrpc_apps gfa;

static const struct fastrpc_channel_info gcinfo[NUM_CHANNELS] = {
	{
		.name = "adsprpc-smd",
		.node = "qcom,msm-audio-ion",
		.group = "lpass_audio",
		.channel = SMD_APPS_QDSP,
	}
};

static void free_mem(struct fastrpc_buf *buf, int cid)
{
	struct fastrpc_apps *me = &gfa;

	if (!IS_ERR_OR_NULL(buf->handle)) {
		if (me->channel[cid].smmu.enabled && buf->phys) {
			ion_unmap_iommu(me->iclient, buf->handle,
					me->channel[cid].smmu.domain_id, 0);
			buf->phys = 0;
		}
		if (!IS_ERR_OR_NULL(buf->virt)) {
			ion_unmap_kernel(me->iclient, buf->handle);
			buf->virt = 0;
		}
		ion_free(me->iclient, buf->handle);
		buf->handle = 0;
	}
}

static void free_map(struct fastrpc_mmap *map, struct file_data *fdata)
{
	struct fastrpc_apps *me = &gfa;
	int cid = fdata->cid;

	if (!IS_ERR_OR_NULL(map->handle)) {
		if (me->channel[cid].smmu.enabled && map->phys) {
			unmap_iommu_mem(map->handle, fdata, 0);
			map->phys = 0;
		}
		if (!IS_ERR_OR_NULL(map->virt)) {
			ion_unmap_kernel(me->iclient, map->handle);
			map->virt = 0;
		}
		ion_free(me->iclient, map->handle);
	}
	map->handle = 0;
}

static int alloc_mem(struct fastrpc_buf *buf, struct file_data *fdata)
{
	struct fastrpc_apps *me = &gfa;
	struct ion_client *clnt = gfa.iclient;
	struct sg_table *sg;
	int err = 0;
	int cid = fdata->cid;
	unsigned int heap;
	buf->handle = 0;
	buf->virt = 0;
	buf->phys = 0;
	heap = me->channel[cid].smmu.enabled ? ION_HEAP(ION_IOMMU_HEAP_ID) :
		ION_HEAP(ION_ADSP_HEAP_ID);
	buf->handle = ion_alloc(clnt, buf->size, SZ_4K, heap, ION_FLAG_CACHED);
	VERIFY(err, 0 == IS_ERR_OR_NULL(buf->handle));
	if (err)
		goto bail;
	buf->virt = ion_map_kernel(clnt, buf->handle);
	VERIFY(err, 0 == IS_ERR_OR_NULL(buf->virt));
	if (err)
		goto bail;
	if (me->channel[cid].smmu.enabled) {
		VERIFY(err, 0 == map_iommu_mem(buf->handle, fdata,
						&buf->phys, buf->size));
		if (err)
			goto bail;
	} else {
		VERIFY(err, 0 != (sg = ion_sg_table(clnt, buf->handle)));
		if (err)
			goto bail;
		buf->phys = sg_dma_address(sg->sgl);
	}
 bail:
	if (err && !IS_ERR_OR_NULL(buf->handle))
		free_mem(buf, cid);
	return err;
}

static void context_list_ctor(struct smq_context_list *me)
{
	INIT_HLIST_HEAD(&me->interrupted);
	INIT_HLIST_HEAD(&me->pending);
	spin_lock_init(&me->hlock);
}

static void context_free(struct smq_invoke_ctx *ctx, bool lock);

static void context_list_dtor(struct fastrpc_apps *me, struct smq_context_list *clst) {
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *n;
	spin_lock(&clst->hlock);
	hlist_for_each_entry_safe(ictx, n, &clst->interrupted, hn) {
		context_free(ictx, 0);
	}
	hlist_for_each_entry_safe(ictx, n, &clst->pending, hn) {
		context_free(ictx, 0);
	}
	spin_unlock(&clst->hlock);
}

static int context_restore_interrupted(struct fastrpc_apps *me,
				struct fastrpc_ioctl_invoke_fd *invokefd,
				int cid, struct smq_invoke_ctx **po)
{
	int err = 0;
	struct smq_invoke_ctx *ctx = 0, *ictx = 0;
	struct hlist_node *pos, *n;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	spin_lock(&me->clst.hlock);
	hlist_for_each_entry_safe(ictx, pos, n, &me->clst.interrupted, hn) {
		if(ictx->pid == current->pid) {
			if(invoke->sc != ictx->sc || ictx->cid != cid)
				err = -1;
			else {
				ctx = ictx;
				hlist_del(&ctx->hn);
				hlist_add_head(&ctx->hn, &me->clst.pending);
			}
			break;
		}
	}
	spin_unlock(&me->clst.hlock);
	if(ctx) {
		*po = ctx;
	}
	return err;
}

#define CMP(aa, bb) ((aa) == (bb) ? 0 : (aa) < (bb) ? -1 : 1)
static int overlap_ptr_cmp(const void *a, const void *b)
{
	struct overlap *pa = *((struct overlap **)a);
	struct overlap *pb = *((struct overlap **)b);
	/* sort with lowest starting buffer first */
	int st = CMP(pa->start, pb->start);
	/* sort with highest ending buffer first */
	int ed = CMP(pb->end, pa->end);
	return st == 0 ? ed : st;
}

static void context_build_overlap(struct smq_invoke_ctx *ctx)
{
	int i;
	remote_arg_t *lpra = ctx->lpra;
	int inbufs = REMOTE_SCALARS_INBUFS(ctx->sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(ctx->sc);
	int nbufs = inbufs + outbufs;
	struct overlap max;
	for (i = 0; i < nbufs; ++i) {
		ctx->overs[i].start = (uintptr_t)lpra[i].buf.pv;
		ctx->overs[i].end = ctx->overs[i].start + lpra[i].buf.len;
		ctx->overs[i].raix = i;
		ctx->overps[i] = &ctx->overs[i];
	}
	sort(ctx->overps, nbufs, sizeof(*ctx->overps), overlap_ptr_cmp, 0);
	max.start = 0;
	max.end = 0;
	for (i = 0; i < nbufs; ++i) {
		if (ctx->overps[i]->start < max.end) {
			ctx->overps[i]->mstart = max.end;
			ctx->overps[i]->mend = ctx->overps[i]->end;
			ctx->overps[i]->offset = max.end -
				ctx->overps[i]->start;
			if (ctx->overps[i]->end > max.end) {
				max.end = ctx->overps[i]->end;
			} else {
				ctx->overps[i]->mend = 0;
				ctx->overps[i]->mstart = 0;
			}
		} else  {
			ctx->overps[i]->mend = ctx->overps[i]->end;
			ctx->overps[i]->mstart = ctx->overps[i]->start;
			ctx->overps[i]->offset = 0;
			max = *ctx->overps[i];
		}
	}
bail:
	return err;
}


static void context_free(struct smq_invoke_ctx *ctx, int remove);

static int context_alloc(struct fastrpc_apps *me, uint32_t kernel,
				struct fastrpc_ioctl_invoke_fd *invokefd,
				struct file_data *fdata,
				struct smq_invoke_ctx **po)
{
	int err = 0, bufs, size = 0;
	struct smq_invoke_ctx *ctx = 0;
	struct smq_context_list *clst = &me->clst;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;

	bufs = REMOTE_SCALARS_INBUFS(invoke->sc) +
			REMOTE_SCALARS_OUTBUFS(invoke->sc);
	if (bufs) {
		size = bufs * sizeof(*ctx->pra);
		if (invokefd->fds)
			size = size + bufs * sizeof(*ctx->fds) +
				bufs * sizeof(*ctx->handles);
	}

	VERIFY(err, 0 != (ctx = kzalloc(sizeof(*ctx) + size, GFP_KERNEL)));
	if (err)
		goto bail;

	INIT_HLIST_NODE(&ctx->hn);
	ctx->pra = (remote_arg_t*)(&ctx[1]);
	ctx->fds = invokefd->fds == 0 ? 0 : (int*)(&ctx->pra[bufs]);
	ctx->handles = invokefd->fds == 0 ? 0 : (struct ion_handle**)(&ctx->fds[bufs]);

	if (!kernel) {
		VERIFY(err, 0 == copy_from_user(ctx->pra, invoke->pra,
					bufs * sizeof(*ctx->pra)));
		if (err)
			goto bail;
	} else {
		memmove(ctx->pra, invoke->pra, bufs * sizeof(*ctx->pra));
	}

	if (invokefd->fds) {
		if (!kernel) {
			VERIFY(err, 0 == copy_from_user(ctx->fds, invokefd->fds,
						bufs * sizeof(*ctx->fds)));
			if (err)
				goto bail;
		} else {
			memmove(ctx->fds, invokefd->fds,
						bufs * sizeof(*ctx->fds));
		}
	}
	ctx->sc = invoke->sc;
	if (REMOTE_SCALARS_INBUFS(ctx->sc) + REMOTE_SCALARS_OUTBUFS(ctx->sc)) {
		VERIFY(err, 0 == context_build_overlap(ctx));
		if (err)
			goto bail;
	}
	ctx->retval = -1;
	ctx->pid = current->pid;
	ctx->tgid = current->tgid;
	init_completion(&ctx->work);
	spin_lock(&clst->hlock);
	hlist_add_head(&ctx->hn, &clst->pending);
	spin_unlock(&clst->hlock);

	*po = ctx;
bail:
	if(ctx && err)
		kfree(ctx);
	return err;
}

static void context_save_interrupted(struct smq_invoke_ctx *ctx)
{
	struct smq_context_list *clst = &ctx->apps->clst;
	spin_lock(&clst->hlock);
	hlist_del(&ctx->hn);
	hlist_add_head(&ctx->hn, &clst->interrupted);
	spin_unlock(&clst->hlock);
}

static void add_dev(struct fastrpc_apps *me, struct fastrpc_device *dev);

static void context_free(struct smq_invoke_ctx *ctx, bool lock)
{
	struct smq_context_list *clst = &ctx->apps->clst;
	struct fastrpc_apps *apps = ctx->apps; 
	struct fastrpc_buf *b;
	int i, bufs;
	if (ctx->smmu) {
		bufs = REMOTE_SCALARS_INBUFS(ctx->sc) + REMOTE_SCALARS_OUTBUFS(ctx->sc);
		if (ctx->fds) {
			for (i = 0; i < bufs; i++)
				if (!IS_ERR_OR_NULL(ctx->handles[i])) {
					ion_unmap_iommu(apps->iclient, ctx->handles[i],
						apps->channel[ctx->cid].smmu.domain_id,
						0);
					ion_free(apps->iclient, ctx->handles[i]);
				}
		}
		iommu_detach_group(apps->channel[ctx->cid].smmu.domain,
					apps->channel[ctx->cid].smmu.group);
	}
	for (i = 0, b = ctx->abufs; i < ctx->nbufs; ++i, ++b)
		free_mem(b, ctx->cid);
	
	kfree(ctx->abufs);
	if (ctx->dev) {
		add_dev(apps, ctx->dev);
		if (ctx->obuf.handle != ctx->dev->buf.handle)
			free_mem(&ctx->obuf, ctx->cid);
	}
	if(lock) {
		spin_lock(&clst->hlock);
	}
	hlist_del(&ctx->hn);
	if(lock) {
		spin_unlock(&clst->hlock);
	}
	kfree(ctx->overps);
	kfree(ctx->overs);
	kfree(ctx);
}

static void context_notify_user(struct smq_invoke_ctx *me, int retval)
{
	me->retval = retval;
	complete(&me->work);
}

static void context_notify_all_users(struct smq_context_list *me, int cid)
{
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *pos, *n;
	spin_lock(&me->hlock);
	hlist_for_each_entry_safe(ictx, pos, n, &me->pending, hn) {
			if(ictx->cid == cid) {
				complete(&ictx->work);
			}
	}
	hlist_for_each_entry_safe(ictx, pos, n, &me->interrupted, hn) {
			if(ictx->cid == cid) {
				complete(&ictx->work);
			}
	}
	spin_unlock(&me->hlock);

}

static int get_page_list(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
		struct fastrpc_buf *ibuf, struct fastrpc_buf *obuf, int cid)
{
	struct smq_phy_page *pgstart, *pages;
	struct smq_invoke_buf *list;
	int i, rlen, err = 0;
	int inbufs = REMOTE_SCALARS_INBUFS(sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(sc);

	LOCK_MMAP(kernel);
	*obuf = *ibuf;
 retry:
	list = smq_invoke_buf_start((remote_arg_t *)obuf->virt, sc);
	pgstart = smq_phy_page_start(sc, list);
	pages = pgstart + 1;
	rlen = obuf->size - ((uintptr_t)pages - (uintptr_t)obuf->virt);
	if (rlen < 0) {
		rlen = ((uintptr_t)pages - (uintptr_t)obuf->virt) - obuf->size;
		obuf->size += buf_page_size(rlen);
		VERIFY(err, 0 == alloc_mem(obuf, ctx->fdata));
		if (err)
			goto bail;
		goto retry;
	}
	pgstart->addr = obuf->phys;
	pgstart->size = obuf->size;
	for (i = 0; i < inbufs + outbufs; ++i) {
		void *buf;
		int len, num;

		list[i].num = 0;
		list[i].pgidx = 0;
		len = pra[i].buf.len;
		VERIFY(err, len >= 0);
		if (err)
			goto bail;
		if (!len)
			continue;
		buf = pra[i].buf.pv;
		num = buf_num_pages(buf, len);
		if (!kernel)
			list[i].num = buf_get_pages(buf, len, num,
				i >= inbufs, pages, rlen / sizeof(*pages));
		else
			list[i].num = 0;
		VERIFY(err, list[i].num >= 0);
		if (err)
			goto bail;
		if (list[i].num) {
			list[i].pgidx = pages - pgstart;
			pages = pages + list[i].num;
		} else if (rlen > sizeof(*pages)) {
			list[i].pgidx = pages - pgstart;
			pages = pages + 1;
		} else {
			if (obuf->handle != ibuf->handle)
				free_mem(obuf, ctx->fdata);
			obuf->size += buf_page_size(sizeof(*pages));
			VERIFY(err, 0 == alloc_mem(obuf, ctx->fdata));
			if (err)
				goto bail;
			goto retry;
		}
		rlen = obuf->size - ((uintptr_t)pages - (uintptr_t)obuf->virt);
	}
	obuf->used = obuf->size - rlen;
 bail:
	if (err && (obuf->handle != ibuf->handle))
		free_mem(obuf, cid);
	UNLOCK_MMAP(kernel);
	return err;
}

static int get_args(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
			remote_arg_t *rpra, remote_arg_t *upra,
			struct fastrpc_buf *ibuf, struct fastrpc_buf **abufs,
			int *nbufs, int *fds, struct ion_handle **handles, int cid)
{
	struct fastrpc_apps *me = &gfa;
	struct smq_invoke_buf *list;
	struct fastrpc_buf *pbuf = ibuf, *obufs = 0;
	struct smq_phy_page *pages;
	void *args;
	int i, rlen, size, used, inh, bufs = 0, err = 0;
	int inbufs = REMOTE_SCALARS_INBUFS(sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	unsigned long len;
	ion_phys_addr_t iova;

	list = smq_invoke_buf_start(rpra, sc);
	pages = smq_phy_page_start(sc, list);
	used = ALIGN(pbuf->used, BALIGN);
	args = (void *)((char *)pbuf->virt + used);
	rlen = pbuf->size - used;
	for (i = 0; i < inbufs + outbufs; ++i) {

		rpra[i].buf.len = pra[i].buf.len;
		if (!rpra[i].buf.len)
			continue;
		if (me->channel[cid].smmu.enabled && fds && (fds[i] >= 0)) {
			len = buf_page_size(pra[i].buf.len);
			handles[i] = ion_import_dma_buf(me->iclient, fds[i]);
			VERIFY(err, 0 == IS_ERR_OR_NULL(handles[i]));
			if (err)
				goto bail;
			VERIFY(err, 0 == map_iommu_mem(handles[i],
						ctx->fdata, &iova, len));
			if (err)
				goto bail;
			rpra[i].buf.pv = pra[i].buf.pv;
			list[i].num = 1;
			pages[list[i].pgidx].addr = iova;
			pages[list[i].pgidx].size = len;
			continue;
		} else if (list[i].num) {
			rpra[i].buf.pv = pra[i].buf.pv;
			continue;
		}
	}

	/* calculate len requreed for copying */
	for (oix = 0; oix < inbufs + outbufs; ++oix) {
		int i = ctx->overps[oix]->raix;
		if (!pra[i].buf.len)
			continue;
		if (list[i].num)
			continue;
		if (ctx->overps[oix]->offset == 0)
			copylen = ALIGN(copylen, BALIGN);
		copylen += ctx->overps[oix]->mend - ctx->overps[oix]->mstart;
	}

	/* alocate new buffer */
	if (copylen > rlen) {
		struct fastrpc_buf *b;
		pbuf->used = pbuf->size - rlen;
		VERIFY(err, 0 != (b = krealloc(obufs,
			 (bufs + 1) * sizeof(*obufs), GFP_KERNEL)));
		if (err)
			goto bail;
		obufs = b;
		pbuf = obufs + bufs;
		pbuf->size = buf_num_pages(0, copylen) * PAGE_SIZE;
		VERIFY(err, 0 == alloc_mem(pbuf, ctx->fdata));
		if (err)
			goto bail;
		bufs++;
		args = pbuf->virt;
		rlen = pbuf->size;

	}

	/* copy non ion buffers */
	for (oix = 0; oix < inbufs + outbufs; ++oix) {
		int i = ctx->overps[oix]->raix;
		int mlen = ctx->overps[oix]->mend - ctx->overps[oix]->mstart;
		if (!pra[i].buf.len)
			continue;
		if (list[i].num)
			continue;

		if (ctx->overps[oix]->offset == 0) {
			rlen -= ALIGN((uintptr_t)args, BALIGN) -
				(uintptr_t)args;
			args = (void *)ALIGN((uintptr_t)args, BALIGN);
		}
		VERIFY(err, rlen >= mlen);
		if (err)
			goto bail;
		list[i].num = 1;
		rpra[i].buf.pv = args - ctx->overps[oix]->offset;
		pages[list[i].pgidx].addr =
			buf_page_start((void *)((uintptr_t)pbuf->phys -
						ctx->overps[oix]->offset +
						 (pbuf->size - rlen)));
		pages[list[i].pgidx].size = buf_num_pages(rpra[i].buf.pv,
						rpra[i].buf.len) * PAGE_SIZE;
		if (i < inbufs) {
			if (!kernel) {
				VERIFY(err, 0 == copy_from_user(rpra[i].buf.pv,
					pra[i].buf.pv, pra[i].buf.len));
				if (err)
					goto bail;
			} else {
				memmove(rpra[i].buf.pv, pra[i].buf.pv,
					pra[i].buf.len);
			}
		}
		args = (void *)((uintptr_t)args + mlen);
		rlen -= mlen;
	}

	if (!kernel) {
		VERIFY(err, 0 == clear_user_outbufs(ctx));
		if (err)
			goto bail;
	}
	for (oix = 0; oix < inbufs + outbufs; ++oix) {
		int i = ctx->overps[oix]->raix;
		if (rpra[i].buf.len && ctx->overps[oix]->mstart)
			dmac_flush_range(rpra[i].buf.pv,
				  (char *)rpra[i].buf.pv + rpra[i].buf.len);
	}
	pbuf->used = pbuf->size - rlen;
	size = sizeof(*rpra) * REMOTE_SCALARS_INHANDLES(sc);
	if (size) {
		inh = inbufs + outbufs;
		if (!kernel) {
			VERIFY(err, 0 == copy_from_user(&rpra[inh], &upra[inh],
							size));
			if (err)
				goto bail;
		} else {
			memmove(&rpra[inh], &upra[inh], size);
		}
	}
	dmac_flush_range(rpra, (char *)rpra + used);
 bail:
	*abufs = obufs;
	*nbufs = bufs;
	return err;
}

static int put_args(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
			remote_arg_t *rpra, remote_arg_t *upra)
{
	int i, inbufs, outbufs, outh, size;
	int err = 0;
	int mflags = 0;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (rpra[i].buf.pv != pra[i].buf.pv) {
			if (!kernel) {
				VERIFY(err, 0 == copy_to_user(pra[i].buf.pv,
					rpra[i].buf.pv, rpra[i].buf.len));
				if (err)
					goto bail;
			} else {
				memmove(pra[i].buf.pv, rpra[i].buf.pv,
							rpra[i].buf.len);
			}
		}
	}
	size = sizeof(*rpra) * REMOTE_SCALARS_OUTHANDLES(sc);
	if (size) {
		outh = inbufs + outbufs + REMOTE_SCALARS_INHANDLES(sc);
		if (!kernel) {
			VERIFY(err, 0 == copy_to_user(&upra[outh], &rpra[outh],
						size));
			if (err)
				goto bail;
		} else {
			memmove(&upra[outh], &rpra[outh], size);
		}
	}
 bail:
	return err;
}

static void inv_args_pre(uint32_t sc, remote_arg_t *rpra)
{
	int i, inbufs, outbufs;
	uintptr_t end;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (!rpra[i].buf.len)
			continue;
		if (buf_page_start(ptr_to_uint64((void *)rpra)) ==
				buf_page_start(rpra[i].buf.pv))
			continue;
		if (!IS_CACHE_ALIGNED((uintptr_t)uint64_to_ptr(rpra[i].buf.pv)))
			dmac_flush_range(uint64_to_ptr(rpra[i].buf.pv),
				(char *)(uint64_to_ptr(rpra[i].buf.pv + 1)));
		end = (uintptr_t)uint64_to_ptr(rpra[i].buf.pv +
							rpra[i].buf.len);
		if (!IS_CACHE_ALIGNED(end))
			dmac_flush_range((char *)end,
				(char *)end + 1);
	}
}

static void inv_args(uint32_t sc, remote_arg64_t *rpra, int used)
{
	int i, inbufs, outbufs;
	int inv = 0;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (buf_page_start(ptr_to_uint64((void *)rpra)) ==
				buf_page_start(rpra[i].buf.pv))
			inv = 1;
		else if (rpra[i].buf.len)
			dmac_inv_range((char *)uint64_to_ptr(rpra[i].buf.pv),
				(char *)uint64_to_ptr(rpra[i].buf.pv
						 + rpra[i].buf.len));
	}

	if (inv || REMOTE_SCALARS_OUTHANDLES(sc))
		dmac_inv_range(rpra, (char *)rpra + used);
}

static int fastrpc_invoke_send(struct smq_invoke_ctx *ctx,
			       uint32_t kernel, uint32_t handle)
{
	struct smq_msg msg = {0};
	struct fastrpc_file *fl = ctx->fl;
	int err = 0, len;
	msg.pid = current->tgid;
	msg.tid = current->pid;
	if (kernel)
		msg.pid = 0;
	msg.invoke.header.ctx = ptr_to_uint64(ctx);
	msg.invoke.header.handle = handle;
	msg.invoke.header.sc = ctx->sc;
	msg.invoke.page.addr = ctx->buf ? ctx->buf->phys : 0;
	msg.invoke.page.size = buf_page_size(ctx->used);
	if (msm_audio_ion_is_smmu_available()
		&& msg.invoke.page.addr != 0)
		msg.invoke.page.addr |= STREAM_ID;
	spin_lock(&fl->apps->hlock);
	len = smd_write(fl->chan->chan, &msg, sizeof(msg));
	spin_unlock(&fl->apps->hlock);
	VERIFY(err, len == sizeof(msg));
	return err;
}

static void fastrpc_deinit(void)
{
	struct fastrpc_apps *me = &gfa;
	int i;

	for (i = 0; i < NUM_CHANNELS; i++) {
		struct fastrpc_chan_ctx *chan = &me->channel[i];
		if (chan->chan) {
			(void)smd_close(chan->chan);
			chan->chan = 0;
		}
		if (chan->smmu.dev)
			chan->smmu.dev = 0;
		if (chan->smmu.mapping)
			chan->smmu.mapping = 0;
	}
}

static void fastrpc_read_handler(int cid)
{
	struct fastrpc_apps *me = &gfa;
	struct smq_invoke_rsp rsp = {0};
	int ret = 0;

	do {
		ret = smd_read_from_cb(me->channel[cid].chan, &rsp,
					sizeof(rsp));
		if (ret != sizeof(rsp))
			break;
		context_notify_user(uint64_to_ptr(rsp.ctx), rsp.retval);
	} while (ret == sizeof(rsp));
}

static void smd_event_handler(void *priv, unsigned event)
{
	struct fastrpc_apps *me = &gfa;
	int cid = (int)(uintptr_t)priv;

	switch (event) {
	case SMD_EVENT_OPEN:
		complete(&me->channel[cid].work);
		break;
	case SMD_EVENT_CLOSE:
		fastrpc_notify_drivers(me, cid);
		break;
	case SMD_EVENT_DATA:
		fastrpc_read_handler(cid);
		break;
	}
}

static int fastrpc_init(void)
{
	int i, err = 0;
	struct fastrpc_apps *me = &gfa;
	struct device_node *node;
	struct fastrpc_smmu *smmu;
	bool enabled = 0;

	spin_lock_init(&me->hlock);
	spin_lock_init(&me->wrlock);
	mutex_init(&me->smd_mutex);
	context_list_ctor(&me->clst);
	for (i = 0; i < RPC_HASH_SZ; ++i)
		INIT_HLIST_HEAD(&me->htbl[i]);
	me->iclient = msm_ion_client_create(ION_HEAP_CARVEOUT_MASK,
						DEVICE_NAME);
	VERIFY(err, 0 == IS_ERR_OR_NULL(me->iclient));
	if (err)
		goto bail;
	for (i = 0; i < NUM_CHANNELS; i++) {
		init_completion(&me->channel[i].work);
		if (!gcinfo[i].node)
			continue;
		smmu = &me->channel[i].smmu;
		node = of_find_compatible_node(NULL, NULL, gcinfo[i].node);
		if (node)
			enabled = of_property_read_bool(node,
						"qcom,smmu-enabled");
		if (enabled)
			smmu->group = iommu_group_find(gcinfo[i].group);
		if (smmu->group)
			smmu->domain = iommu_group_get_iommudata(smmu->group);
		if (!IS_ERR_OR_NULL(smmu->domain)) {
			smmu->domain_id = msm_find_domain_no(smmu->domain);
			if (smmu->domain_id >= 0)
				smmu->enabled = enabled;
		}
	}
	return 0;

bail:
	return err;
}

static void free_dev(struct fastrpc_device *dev, struct file_data *fdata)
{
	if (dev) {
		free_mem(&dev->buf, fdata);
		kfree(dev);
		module_put(THIS_MODULE);
	}
}

static int alloc_dev(struct fastrpc_device **dev, struct file_data *fdata)
{
	int err = 0;
	struct fastrpc_device *fd = 0;

	VERIFY(err, 0 != try_module_get(THIS_MODULE));
	if (err)
		goto bail;
	VERIFY(err, 0 != (fd = kzalloc(sizeof(*fd), GFP_KERNEL)));
	if (err)
		goto bail;

	INIT_HLIST_NODE(&fd->hn);

	fd->buf.size = PAGE_SIZE;
	VERIFY(err, 0 == alloc_mem(&fd->buf, fdata));
	if (err)
		goto bail;
	fd->tgid = current->tgid;

	*dev = fd;
 bail:
	if (err)
		free_dev(fd, fdata);
	return err;
}

static int get_dev(struct fastrpc_apps *me, struct file_data *fdata,
			struct fastrpc_device **rdev)
{
	struct hlist_head *head;
	struct fastrpc_device *dev = 0, *devfree = 0;
	struct hlist_node *n;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);
	int err = 0;

	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_for_each_entry_safe(dev, n, head, hn) {
		if (dev->tgid == current->tgid) {
			hlist_del(&dev->hn);
			devfree = dev;
			break;
		}
	}
	spin_unlock(&me->hlock);
	VERIFY(err, devfree != 0);
	if (err)
		goto bail;
	*rdev = devfree;
 bail:
	if (err) {
		free_dev(devfree, fdata);
		err = alloc_dev(rdev, fdata);
	}
	return err;
}

static void add_dev(struct fastrpc_apps *me, struct fastrpc_device *dev)
{
	struct hlist_head *head;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);

	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_add_head(&dev->hn, head);
	spin_unlock(&me->hlock);
	return;
}

static int fastrpc_release_current_dsp_process(int cid);

static int fastrpc_internal_invoke(struct fastrpc_apps *me, uint32_t mode,
			uint32_t kernel, struct fastrpc_ioctl_invoke_fd *invokefd,
			int cid)
{
	struct smq_invoke_ctx *ctx = 0;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	int interrupted = 0;
	int err = 0;

	if(!kernel) {
		VERIFY(err, 0 == context_restore_interrupted(me, invokefd, cid, &ctx));
		if (err)
			goto bail;
		if(ctx) 
			goto wait;
	}

	VERIFY(err, 0 == context_alloc(me, kernel, invokefd, cid, &ctx));
	if (err)
		goto bail;

	if (me->channel[cid].smmu.enabled) {
		VERIFY(err, 0 == iommu_attach_group(
						me->channel[cid].smmu.domain,
						me->channel[cid].smmu.group));
		if (err)
			goto bail;
		ctx->smmu = 1;
	}
	if (REMOTE_SCALARS_LENGTH(ctx->sc)) {
		VERIFY(err, 0 == get_dev(me, cid, &ctx->dev));
		if (err)
			goto bail;
		VERIFY(err, 0 == get_page_list(kernel, ctx->sc, ctx->pra, &ctx->dev->buf,
						&ctx->obuf, cid));
		if (err)
			goto bail;
		ctx->rpra = (remote_arg_t *)ctx->obuf.virt;
		VERIFY(err, 0 == get_args(kernel, ctx->sc, ctx->pra, ctx->rpra, invoke->pra,
					&ctx->obuf, &ctx->abufs, &ctx->nbufs, ctx->fds, ctx->handles, cid));
		if (err)
			goto bail;
	}

	inv_args_pre(ctx->sc, ctx->rpra);
	if (FASTRPC_MODE_SERIAL == mode)
		inv_args(ctx->sc, ctx->rpra, ctx->obuf.used);
	VERIFY(err, 0 == fastrpc_invoke_send(me, kernel, invoke->handle, ctx->sc,
						ctx, &ctx->obuf));
	if (err)
		goto bail;
	if (FASTRPC_MODE_PARALLEL == mode)
		inv_args(ctx->sc, ctx->rpra, ctx->obuf.used);
wait:
	if(kernel)
			wait_for_completion(&ctx->work);
	else {
		interrupted = wait_for_completion_interruptible(&ctx->work);
		VERIFY(err, 0 == (err = interrupted));
		if (err)
			goto bail;
	}
	VERIFY(err, 0 == (err = ctx->retval));
	if (err)
		goto bail;
	VERIFY(err, 0 == put_args(kernel, ctx->sc, ctx->pra, ctx->rpra, invoke->pra));
	if (err)
		goto bail;
 bail:
	if (ctx && interrupted == -ERESTARTSYS) {
		context_save_interrupted(ctx);
		err = -ERESTARTSYS;
	} else if(ctx) {
		context_free(ctx, 1);
	}
	return err;
}

static int fastrpc_create_current_dsp_process(int cid)
{
	int err = 0;
	struct fastrpc_ioctl_invoke_fd ioctl;
	struct fastrpc_apps *me = &gfa;
	remote_arg_t ra[1];
	int tgid = 0;

	tgid = fdata->tgid;
	ra[0].buf.pv = &tgid;
	ra[0].buf.len = sizeof(tgid);
	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(0, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
		FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
	return err;
}

static int fastrpc_release_current_dsp_process(struct file_data *fdata)
{
	int err = 0;
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[1];
	int tgid = 0;

	tgid = fdata->tgid;
	ra[0].buf.pv = &tgid;
	ra[0].buf.len = sizeof(tgid);
	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(1, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
		FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
	return err;
}

static int fastrpc_mmap_on_dsp(struct fastrpc_apps *me,
					 struct fastrpc_ioctl_mmap *mmap,
					 struct smq_phy_page *pages,
					 struct file_data *fdata, int num)
{
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[3];
	int err = 0;
	struct {
		int pid;
		uint32_t flags;
		uintptr_t vaddrin;
		int num;
	} inargs;

	struct {
		uintptr_t vaddrout;
	} routargs;
	inargs.pid = current->tgid;
	inargs.vaddrin = (uintptr_t)map->va;
	inargs.flags = flags;
	inargs.num = fl->apps->compat ? num * sizeof(page) : num;
	ra[0].buf.pv = (void *)&inargs;
	ra[0].buf.len = sizeof(inargs);
	page.addr = map->phys;
	if (msm_audio_ion_is_smmu_available() && flags != ADSP_MMAP_HEAP_ADDR)
		page.addr |= STREAM_ID;
	page.size = map->size;
	ra[1].buf.pv = (void *)&page;
	ra[1].buf.len = num * sizeof(page);

	ra[2].buf.pv = (void *)&routargs;
	ra[2].buf.len = sizeof(routargs);

	ioctl.inv.handle = 1;
	if (fl->apps->compat)
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(4, 2, 1);
	else
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(2, 2, 1);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(fl,
		FASTRPC_MODE_PARALLEL, 1, &ioctl)));
	map->raddr = (uintptr_t)routargs.vaddrout;
	if (err)
		goto bail;
	if (flags == ADSP_MMAP_HEAP_ADDR) {
		struct scm_desc desc = {0};
		desc.args[0] = TZ_PIL_AUTH_QDSP6_PROC;
		desc.args[1] = map->phys;
		desc.args[2] = map->size;
		desc.arginfo = SCM_ARGS(3);
		err = scm_call2(SCM_SIP_FNID(SCM_SVC_PIL,
			TZ_PIL_PROTECT_MEM_SUBSYS_ID), &desc);
	}

bail:
	return err;
}


static int fastrpc_munmap_on_dsp(struct fastrpc_file *fl,
				 struct fastrpc_mmap *map)
{
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[1];
	int err = 0;
	struct {
		int pid;
		uintptr_t vaddrout;
		ssize_t size;
	} inargs;

	inargs.pid = current->tgid;
	inargs.size = munmap->size;
	inargs.vaddrout = munmap->vaddrout;
	ra[0].buf.pv = &inargs;
	ra[0].buf.len = sizeof(inargs);

	ioctl.inv.handle = 1;
	if (me->compat)
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(5, 1, 0);
	else
		ioctl.inv.sc = REMOTE_SCALARS_MAKE(3, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
		FASTRPC_MODE_PARALLEL, 1, &ioctl, fdata)));
	return err;
}

static int fastrpc_internal_munmap(struct fastrpc_apps *me,
				   struct file_data *fdata,
				   struct fastrpc_ioctl_munmap *munmap)
{
	int err = 0;
	struct fastrpc_mmap *map = 0, *mapfree = 0;
	struct hlist_node *pos, *n;
	VERIFY(err, 0 == (err = fastrpc_munmap_on_dsp(me, munmap, fdata->cid)));
	if (err)
		goto bail;
	spin_lock(&fdata->hlock);
	hlist_for_each_entry_safe(map, pos, n, &fdata->hlst, hn) {
		if (map->vaddrout == munmap->vaddrout &&
			 map->size == munmap->size) {
			hlist_del(&map->hn);
			mapfree = map;
			map = 0;
			break;
		}
	}
	spin_unlock(&fdata->hlock);
bail:
	if (mapfree) {
		free_map(mapfree, fdata->cid);
		kfree(mapfree);
	}
	return err;
}


static int fastrpc_internal_mmap(struct fastrpc_apps *me,
				 struct file_data *fdata,
				 struct fastrpc_ioctl_mmap *mmap)
{
	struct ion_client *clnt = gfa.iclient;
	struct fastrpc_mmap *map = 0;
	struct smq_phy_page *pages = 0;
	struct ion_handle *handles;
	void *buf;
	unsigned long len;
	int num;
	int err = 0;

	VERIFY(err, 0 != (map = kzalloc(sizeof(*map), GFP_KERNEL)));
	if (err)
		goto bail;
	map->handle = ion_import_dma_buf(clnt, mmap->fd);
	VERIFY(err, 0 == IS_ERR_OR_NULL(map->handle));
	if (err)
		goto bail;
	map->virt = ion_map_kernel(clnt, map->handle);
	VERIFY(err, 0 == IS_ERR_OR_NULL(map->virt));
	if (err)
		goto bail;
	num = buf_num_pages(buf, len);
	VERIFY(err, 0 != (pages = kzalloc(num * sizeof(*pages), GFP_KERNEL)));
	if (err)
		goto bail;

	if (me->channel[fdata->cid].smmu.enabled) {
		handles = ion_import_dma_buf(clnt, mmap->fd);
		VERIFY(err, 0 == IS_ERR_OR_NULL(handles));
		if (err)
			goto bail;
		VERIFY(err, 0 == ion_map_iommu(clnt, handles,
				me->channel[fdata->cid].smmu.domain_id, 0,
				SZ_4K, 0, &map->phys, &len, 0, 0));
		if (err)
			goto bail;
		pages->addr = map->phys;
		pages->size = len;
		num = 1;
	} else {
		VERIFY(err, 0 < (num = buf_get_pages(buf, len, num, 1,
						pages, num, &me->range)));
		if (err)
			goto bail;
	}
	map->refs = 1;
	INIT_HLIST_NODE(&map->hn);
	map->vaddrin = (uintptr_t *)buf;
	map->vaddrout = vaddrout;
	map->size = len;
	if (ppages)
		*ppages = pages;
	pages = 0;
	if (pnpages)
		*pnpages = num;
	if (ppmap)
		*ppmap = map;
	map = 0;
 bail:
	if (map)
		free_map(map, fdata);
	kfree(pages);
	return err;

}

static int fastrpc_internal_mmap(struct fastrpc_apps *me,
				 struct file_data *fdata,
				 struct fastrpc_ioctl_mmap *mmap)
{

	struct fastrpc_mmap *map = 0;
	struct smq_phy_page *pages = 0;
	int num = 0;
	int err = 0;
	VERIFY(err, 0 == map_buffer(me, fdata, mmap->fd, (char *)mmap->vaddrin,
					mmap->size, &map, &pages, &num));
	VERIFY(err, 0 == fastrpc_mmap_on_dsp(me, mmap, pages, fdata, num));
	if (err)
		goto bail;
	map->vaddrout = mmap->vaddrout;
	spin_lock(&fdata->hlock);
	hlist_add_head(&map->hn, &fdata->hlst);
	spin_unlock(&fdata->hlock);
 bail:
	if (err && map) {
		free_map(map, fdata);
		kfree(map);
	}
	kfree(pages);
	return err;
}

static void cleanup_current_dev(struct file_data *fdata)
{
	struct fastrpc_apps *me = &gfa;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);
	struct hlist_head *head;
	struct hlist_node *n;
	struct fastrpc_device *dev, *devfree;

 rnext:
	devfree = dev = 0;
	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_for_each_entry_safe(dev, n, head, hn) {
		if (dev->tgid == current->tgid) {
			hlist_del(&dev->hn);
			devfree = dev;
			break;
		}
	}
	spin_unlock(&me->hlock);
	if (devfree) {
		free_dev(devfree, fdata);
		goto rnext;
	}
	return;
}

static void fastrpc_channel_close(struct kref *kref)
{
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_channel_context *ctx;
	int cid;

	ctx = container_of(kref, struct fastrpc_channel_context, kref);
	smd_close(ctx->chan);
	ctx->chan = 0;
	mutex_unlock(&me->smd_mutex);
	cid = ctx - &me->channel[0];
	pr_info("'closed /dev/%s c %d %d'\n", gcinfo[cid].name,
						MAJOR(me->dev_no), cid);
}

static int fastrpc_device_release(struct inode *inode, struct file *file)
{
	struct file_data *fdata = (struct file_data *)file->private_data;
	struct fastrpc_apps *me = &gfa;
	struct smq_context_list *clst = &me->clst;
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *n;
	int cid = MINOR(inode->i_rdev);

	(void)fastrpc_release_current_dsp_process(cid);
	cleanup_current_dev(cid);
	spin_lock(&clst->hlock);
	hlist_for_each_entry_safe(ictx, n, &clst->interrupted, hn) {
		if (ictx->tgid == current->tgid)
			context_free(ictx, 0);
	}
	spin_unlock(&clst->hlock);
	if (fdata) {
		struct fastrpc_mmap *map = 0;
		struct hlist_node *pos, *n;
		file->private_data = 0;
		hlist_for_each_entry_safe(map, pos, n, &fdata->hlst, hn) {
			hlist_del(&map->hn);
			free_map(map, cid);
			kfree(map);
		}
		kfree(fdata);
		kref_put_mutex(&me->channel[cid].kref, fastrpc_channel_close,
				&me->smd_mutex);
	}
	return 0;
}

static int fastrpc_device_open(struct inode *inode, struct file *filp)
{
	int cid = MINOR(inode->i_rdev);
	int err = 0, ssrcount;
	struct fastrpc_apps *me = &gfa;

	mutex_lock(&me->smd_mutex);
	ssrcount = me->channel[cid].ssrcount;
	if ((kref_get_unless_zero(&me->channel[cid].kref) == 0) ||
		(me->channel[cid].chan == 0)) {
		VERIFY(err, 0 == smd_named_open_on_edge(
					FASTRPC_SMD_GUID,
					gcinfo[cid].channel,
					&me->channel[cid].chan, (void*)cid,
					smd_event_handler));
		if (err)
			goto smd_bail;
		VERIFY(err, 0 != wait_for_completion_timeout(
							&me->channel[cid].work,
							RPC_TIMEOUT));
		if (err)
			goto completion_bail;
		kref_init(&me->channel[cid].kref);
		pr_info("'opened /dev/%s c %d %d'\n", gcinfo[cid].name,
						MAJOR(me->dev_no), cid);
		if (me->channel[cid].ssrcount !=
				 me->channel[cid].prevssrcount) {
			if (fastrpc_mmap_remove_ssr(fl))
				pr_err("ADSPRPC: SSR: Failed to unmap remote heap\n");
			me->channel[cid].prevssrcount =
						me->channel[cid].ssrcount;
		}
	}
	mutex_unlock(&me->smd_mutex);

	filp->private_data = 0;
	if (0 != try_module_get(THIS_MODULE)) {
		struct file_data *fdata = 0;
		/* This call will cause a dev to be created
		 * which will addref this module
		 */
		VERIFY(err, 0 != (fdata = kzalloc(sizeof(*fdata), GFP_KERNEL)));
		if (err)
			goto bail;

		spin_lock_init(&fdata->hlock);
		INIT_HLIST_HEAD(&fdata->hlst);
		fdata->cid = cid;
		fdata->tgid = current->tgid;
		fdata->ssrcount = ssrcount;

		filp->private_data = fdata;
bail:
		if (err) {
			if (fdata) {
				cleanup_current_dev(fdata);
				kfree(fdata);
			}
			kref_put_mutex(&me->channel[cid].kref,
					fastrpc_channel_close, &me->smd_mutex);
		}
		module_put(THIS_MODULE);
	}
	return err;

completion_bail:
	smd_close(me->channel[cid].chan);
	me->channel[cid].chan = 0;
smd_bail:
	mutex_unlock(&me->smd_mutex);
	return err;
}

static long fastrpc_device_ioctl(struct file *file, unsigned int ioctl_num,
				 unsigned long ioctl_param)
{
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_ioctl_invoke_fd invokefd;
	struct fastrpc_ioctl_invoke *invoke = &invokefd.inv;
	struct fastrpc_ioctl_mmap mmap;
	struct fastrpc_ioctl_munmap munmap;
	struct fastrpc_ioctl_init init;
	void *param = (char *)ioctl_param;
	struct file_data *fdata = (struct file_data *)file->private_data;
	int size = 0, err = 0;

	switch (ioctl_num) {
	case FASTRPC_IOCTL_INVOKE_FD:
	case FASTRPC_IOCTL_INVOKE:
		invokefd.fds = 0;
		size = (ioctl_num == FASTRPC_IOCTL_INVOKE) ?
				sizeof(*invoke) : sizeof(invokefd);
		VERIFY(err, 0 == copy_from_user(&invokefd, param, size));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_invoke(me, fdata->mode,
							0, &invokefd, fdata->cid)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_MMAP:
		VERIFY(err, 0 == copy_from_user(&mmap, param,
						sizeof(mmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_mmap(me, fdata,
									&mmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == copy_to_user(param, &mmap, sizeof(mmap)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_MUNMAP:
		VERIFY(err, 0 == copy_from_user(&munmap, param,
						sizeof(munmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_munmap(me, fdata,
								&munmap)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_SETMODE:
		switch ((uint32_t)ioctl_param) {
		case FASTRPC_MODE_PARALLEL:
		case FASTRPC_MODE_SERIAL:
			fl->mode = (uint32_t)ioctl_param;
			break;
		default:
			err = -ENOTTY;
			break;
		}
		break;
	case FASTRPC_IOCTL_INIT:
		VERIFY(err, 0 == copy_from_user(&p.init, param,
						sizeof(p.init)));
		if (err)
			goto bail;
		VERIFY(err, 0 == fastrpc_init_process(fl, &p.init));
		if (err)
			goto bail;
		break;

	default:
		err = -ENOTTY;
		break;
	}
 bail:
	return err;
}

static int fastrpc_restart_notifier_cb(struct notifier_block *nb,
					unsigned long code,
					void *data)
{
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_chan_ctx *ctx;
	int cid;

	ctx = container_of(nb, struct fastrpc_chan_ctx, nb);
	cid = ctx - &me->channel[0];
	if (code == SUBSYS_BEFORE_SHUTDOWN) {
		mutex_lock(&me->smd_mutex);
		ctx->ssrcount++;
		if (ctx->chan) {
			smd_close(ctx->chan);
			ctx->chan = 0;
			pr_info("'closed /dev/%s c %d %d'\n", gcinfo[cid].name,
						MAJOR(me->dev_no), cid);
		}
		mutex_unlock(&me->smd_mutex);
		fastrpc_notify_drivers(me, cid);
	}
	spin_lock(&me->hlock);
	hlist_add_head(&fl->hn, &me->drivers);
	spin_unlock(&me->hlock);

	return NOTIFY_DONE;
}

static const struct file_operations fops = {
	.open = fastrpc_device_open,
	.release = fastrpc_device_release,
	.unlocked_ioctl = fastrpc_device_ioctl,
	.compat_ioctl = compat_fastrpc_device_ioctl,
};

static int adsp_mem_driver_probe(struct platform_device *pdev)
{
	struct fastrpc_apps *me = &gfa;
	struct device *dev = &pdev->dev;

	if (of_device_is_compatible(dev->of_node,
					"qcom,msm-adsprpc-mem-region")) {
		me->adsp_mem_device = dev;
		return 0;
	}
	return -EINVAL;
}

static struct of_device_id adsp_mem_match_table[] = {
	{ .compatible = "qcom,msm-adsprpc-mem-region" },
	{}
};

static struct platform_driver adsp_memory_driver = {
	.probe = adsp_mem_driver_probe,
	.driver = {
		.name = "msm-adsprpc-mem-region",
		.of_match_table = adsp_mem_match_table,
		.owner = THIS_MODULE,
	},
};

static int __init fastrpc_device_init(void)
{
	struct fastrpc_apps *me = &gfa;
	struct device_node *node;
	struct platform_device *pdev;
	struct iommu_group *group;
	struct iommu_domain *domain;
	int err = 0, i;

	memset(me, 0, sizeof(*me));

	fastrpc_init(me);
	VERIFY(err, 0 == alloc_chrdev_region(&me->dev_no, 0, NUM_CHANNELS,
					DEVICE_NAME));
	if (err)
		goto alloc_chrdev_bail;
	cdev_init(&me->cdev, &fops);
	me->cdev.owner = THIS_MODULE;
	VERIFY(err, 0 == cdev_add(&me->cdev, MKDEV(MAJOR(me->dev_no), 0),
				NUM_CHANNELS));
	if (err)
		goto cdev_init_bail;
	me->class = class_create(THIS_MODULE, "fastrpc");
	VERIFY(err, !IS_ERR(me->class));
	if (err)
		goto class_create_bail;
	me->compat = (NULL == fops.compat_ioctl) ? 0 : 1;
	for (i = 0; i < NUM_CHANNELS; i++) {
		me->channel[i].dev = device_create(me->class, NULL,
					MKDEV(MAJOR(me->dev_no), i),
					NULL, gcinfo[i].name);
		VERIFY(err, !IS_ERR(me->channel[i].dev));
		if (err)
			goto device_create_bail;
		me->channel[i].ssrcount = 0;
		me->channel[i].prevssrcount = 0;
		me->channel[i].nb.notifier_call = fastrpc_restart_notifier_cb,
		(void)subsys_notif_register_notifier(gcinfo[i].subsys,
							&me->channel[i].nb);
		if (!gcinfo[i].node)
			continue;
		node = of_find_compatible_node(NULL, NULL, gcinfo[i].node);
		if (node) {
			pdev = of_find_device_by_node(node);
			if (pdev) {
				me->channel[i].smmu.dev = &pdev->dev;
				me->channel[i].smmu.enabled = 1;
				me->channel[i].smmu.cb = 1;
				dev_dbg(me->channel[i].dev,
					"%s: Using audio Context bank\n",
					__func__);
			}
		}
	}
	group = iommu_group_find("lpass_audio");
	if (!group) {
		pr_debug("Failed to find group lpass_audio deferred\n");
		err = -1;
		goto register_bail;
	}
	domain = iommu_group_get_iommudata(group);
	if (IS_ERR_OR_NULL(domain)) {
		pr_err("Failed to get domain data for group %p\n",
				group);
		err = -1;
		goto register_bail;
	}
	me->domain_id = msm_find_domain_no(domain);
	if (me->domain_id < 0) {
		pr_err("Failed to get domain index for domain %p\n",
				domain);
		err = -1;
		goto register_bail;
	}
	pr_debug("domain=%p, domain_id=%d, group=%p\n", domain,
			me->domain_id, group);
	err = platform_driver_register(&adsp_memory_driver);
	if (err) {
		pr_err("ADSPRPC: Failed to register adsp memory driver");
		goto register_bail;
	}

	return 0;

device_create_bail:
	class_destroy(me->class);
class_create_bail:
	cdev_del(&me->cdev);
cdev_init_bail:
	unregister_chrdev_region(me->dev_no, NUM_CHANNELS);
alloc_chrdev_bail:
	fastrpc_deinit();
register_bail:
	return err;
}

static void __exit fastrpc_device_exit(void)
{
	struct fastrpc_apps *me = &gfa;
	int i;

	fastrpc_file_list_dtor(me);
	fastrpc_deinit();
	for (i = 0; i < NUM_CHANNELS; i++) {
		device_destroy(me->class, MKDEV(MAJOR(me->dev_no), i));
		subsys_notif_unregister_notifier(gcinfo[i].subsys,
						&me->channel[i].nb);
	}
	class_destroy(me->class);
	cdev_del(&me->cdev);
	unregister_chrdev_region(me->dev_no, NUM_CHANNELS);
}

late_initcall(fastrpc_device_init);
module_exit(fastrpc_device_exit);

MODULE_LICENSE("GPL v2");
