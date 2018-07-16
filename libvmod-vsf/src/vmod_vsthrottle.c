/*-
 * Copyright (c) 2013-2015 Varnish Software
 * All rights reserved.
 *
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "cache/cache.h"

#include "vtim.h"
#include "vsha256.h"
#include "vtree.h"

#include "vcc_if.h"


/* Represents a token bucket for a specific key. */
struct tbucket {
	unsigned		magic;
#define TBUCKET_MAGIC		0x53345eb9
	unsigned char		digest[SHA256_LEN];
	double			last_used;
	double			period;
	double			block;
	long			tokens;
	long			capacity;
	VRB_ENTRY(tbucket)	tree;
};

static int
keycmp(const struct tbucket *b1, const struct tbucket *b2)
{
	return (memcmp(b1->digest, b2->digest, sizeof b1->digest));
}

VRB_HEAD(tbtree, tbucket);
VRB_PROTOTYPE_STATIC(tbtree, tbucket, tree, keycmp);
VRB_GENERATE_STATIC(tbtree, tbucket, tree, keycmp);

/* To lessen potential mutex contention, we partition the buckets into
   N_PART partitions.  */
#define N_PART		16 /* must be 2^n */
#define N_PART_MASK	(N_PART - 1)

static unsigned n_init;
static pthread_mutex_t init_mtx = PTHREAD_MUTEX_INITIALIZER;

/* GC_INTVL: How often (in #calls per partition) we invoke the garbage
   collector. */
#define GC_INTVL	1000
static void run_gc(double now, unsigned part);

static struct vsthrottle {
	unsigned		magic;
#define VSTHROTTLE_MAGIC	0x99fdbef8
	pthread_mutex_t		mtx;
	struct tbtree		buckets;
	unsigned		gc_count;
} vsthrottle[N_PART];

static struct tbucket *
tb_alloc(const unsigned char *digest, long limit, double period, double now)
{
	struct tbucket *tb = malloc(sizeof *tb);
	AN(tb);

	memcpy(tb->digest, digest, sizeof tb->digest);
	tb->magic = TBUCKET_MAGIC;
	tb->last_used = now;
	tb->period = period;
	tb->block = 0.;
	tb->tokens = limit;
	tb->capacity = limit;

	return (tb);
}

static struct tbucket *
get_bucket(const unsigned char *digest, long limit, double period, double now)
{
	struct tbucket *b;
	struct tbucket k;
	unsigned part = digest[0] & N_PART_MASK;
	struct vsthrottle *v = &vsthrottle[part];

	INIT_OBJ(&k, TBUCKET_MAGIC);
	memcpy(&k.digest, digest, sizeof k.digest);
	b = VRB_FIND(tbtree, &v->buckets, &k);
	if (b) {
		CHECK_OBJ_NOTNULL(b, TBUCKET_MAGIC);
	} else {
		b = tb_alloc(digest, limit, period, now);
		AZ(VRB_INSERT(tbtree, &v->buckets, b));
	}
	return (b);
}

static void
calc_tokens(struct tbucket *b, double now)
{
	double delta = now - b->last_used;
	assert(delta >= 0);

	b->tokens += (long) ((delta / b->period) * b->capacity);
	if (b->tokens > b->capacity)
		b->tokens = b->capacity;
	/* VSL(SLT_VCL_Log, 0, "tokens: %ld", b->tokens); */
}

static
void do_digest(unsigned char *out, const char *s, VCL_INT l, VCL_DURATION p,
	       VCL_DURATION b)
{
	SHA256_CTX sctx;

	SHA256_Init(&sctx);
	SHA256_Update(&sctx, s, strlen(s));
	SHA256_Update(&sctx, &l, sizeof (l));
	SHA256_Update(&sctx, &p, sizeof (p));
	SHA256_Update(&sctx, &b, sizeof (b));
	SHA256_Final(out, &sctx);
}

VCL_BOOL
vmod_is_denied(VRT_CTX, VCL_STRING key, VCL_INT limit, VCL_DURATION period,
               VCL_DURATION block)
{
	unsigned ret = 1, blocked = 0;
	struct tbucket *b;
	double now;

	struct vsthrottle *v;
	unsigned char digest[SHA256_LEN];
	unsigned part;

	(void)ctx;

	if (!key)
		return (1);
	do_digest(digest, key, limit, period, block);

	part = digest[0] & N_PART_MASK;
	v = &vsthrottle[part];
	AZ(pthread_mutex_lock(&v->mtx));
	now = VTIM_mono();
	b = get_bucket(digest, limit, period, now);
	calc_tokens(b, now);
	if (block > 0. && now < b->block) {
		blocked = 1;
		b->last_used = now;
	}
	if (b->tokens > 0) {
		b->tokens -= 1;
		if (!blocked)
			ret = 0;
		b->last_used = now;
	}
	else if (block > 0. && !blocked)
		b->block = now + block;

	if (block > 0. && !ret && !blocked)
		b->block = 0.;

	v->gc_count++;
	if (v->gc_count == GC_INTVL) {
		run_gc(now, part);
		v->gc_count = 0;
	}

	AZ(pthread_mutex_unlock(&v->mtx));
	return (ret);
}

/* Clean up expired entries. */
static void
run_gc(double now, unsigned part)
{
	struct tbucket *x, *y;
	struct tbtree *buckets = &vsthrottle[part].buckets;

	/* XXX: Assert mtx is held ... */
	VRB_FOREACH_SAFE(x, tbtree, buckets, y) {
		CHECK_OBJ_NOTNULL(x, TBUCKET_MAGIC);
		if (now - x->last_used > x->period) {
			VRB_REMOVE(tbtree, buckets, x);
			free(x);
		}
	}
}

static void
fini(void *priv)
{
	assert(priv == &n_init);

	AZ(pthread_mutex_lock(&init_mtx));
	assert(n_init > 0);
	n_init--;
	if (n_init == 0) {
		struct tbucket *x, *y;
		unsigned p;

		for (p = 0; p < N_PART; ++p ) {
			struct vsthrottle *v = &vsthrottle[p];
			VRB_FOREACH_SAFE(x, tbtree, &v->buckets, y) {
				CHECK_OBJ_NOTNULL(x, TBUCKET_MAGIC);
				VRB_REMOVE(tbtree, &v->buckets, x);
				free(x);
			}
		}
	}
	AZ(pthread_mutex_unlock(&init_mtx));
}

int
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	if (e != VCL_EVENT_LOAD)
		return (0);

	(void)ctx;

	priv->priv = &n_init;
	priv->free = fini;
	AZ(pthread_mutex_lock(&init_mtx));
	if (n_init == 0) {
		unsigned p;
		for (p = 0; p < N_PART; ++p) {
			struct vsthrottle *v = &vsthrottle[p];
			v->magic = VSTHROTTLE_MAGIC;
			AZ(pthread_mutex_init(&v->mtx, NULL));
			VRB_INIT(&v->buckets);
		}
	}
	n_init++;
	AZ(pthread_mutex_unlock(&init_mtx));
	return (0);
}
