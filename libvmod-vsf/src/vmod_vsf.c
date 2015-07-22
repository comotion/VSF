/*
 * Copyright (c) 2015, Federico G. Schwindt <fgsch@lodoss.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * From libvmod-shield:
 *
 * Copyright (c) 2011 Varnish Software AS
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>

#include "cache/cache.h"

#include "vrt.h"
#include "vcl.h"

#include "vcc_if.h"

#ifndef VRT_CTX
#define VRT_CTX         const struct vrt_ctx *ctx
#endif

#define FORM_URLENCODED	"application/x-www-form-urlencoded"

int	VTCP_linger(int sock, int linger);	/* From vtcp.h */


static int
vsf_iter_req_body(struct req *req, void *priv, void *ptr, size_t len)
{
	(void)req;

	VSB_bcat(priv, ptr, len);
	return (0);
}

/* urldecode function based on strlcpy from Todd C. Miller */
static size_t
vsf_urldecode(char *dst, const char *src, size_t siz)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;

	if (n != 0 && --n != 0) {
		do {
			if (*s == '%' && s[1] && s[2]) {
				if (isxdigit(s[1]) && isxdigit(s[2])) {
#define ORD(c)	((c) >= 'A' ? ((c) & 0xDF) - 'A' + 10 : (c) - '0')
					*d++ = ORD(s[1]) << 4 | ORD(s[2]);
					s += 3;
#undef ORD
				} else
					*d++ = *s++;
			} else if (*s == '+') {
				*d++ = ' ';
				s++;
			} else if ((*d++ = *s++) == '\0')
				break;
		} while (--n != 0);
	}
	if (n == 0) {
		if (siz != 0)
			*d = '\0';
		while (*s++)
			;
	}
	return (s - src - 1);
}

VCL_STRING
vmod_body(VRT_CTX, struct vmod_priv * priv, VCL_BYTES maxsize)
{
	struct vsb *vsb;
	const char *p;
	ssize_t size;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);

	if (!http_GetHdr(ctx->req->http, H_Content_Type, &p))
		return (NULL);
	if (strncasecmp(p, FORM_URLENCODED, sizeof(FORM_URLENCODED) - 1)) {
		VSLb(ctx->vsl, SLT_Error,
		    "vsf.body: Unsupported form encoding (%s)", p);
		return (NULL);
	}
	size = VRT_CacheReqBody(ctx, maxsize);
	if (size <= 0)
		return (NULL);
	vsb = VSB_new(NULL, NULL, size + 1, 0);
	AN(vsb);
	if (VRB_Iterate(ctx->req, vsf_iter_req_body, vsb) == -1) {
		VSLb(ctx->vsl, SLT_Error,
		    "vsf.body: Problem fetching the body");
		VSB_delete(vsb);
		return (NULL);
	}
	AZ(VSB_finish(vsb));
	vsb->s_len = vsf_urldecode(VSB_data(vsb), VSB_data(vsb),
	    VSB_len(vsb));
	priv->free = (vmod_priv_free_f *)VSB_delete;
	priv->priv = vsb;
	return (VSB_data(vsb));
}

VCL_STRING
vmod_urldecode(VRT_CTX, VCL_STRING s)
{
	unsigned u, v;
	char *p;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (!s) {
		VSLb(ctx->vsl, SLT_Error, "vsf.urldecode: No input");
		return (NULL);
	}
	u = WS_Reserve(ctx->ws, 0);
	p = ctx->ws->f;
	v = vsf_urldecode(p, s, u);
	if (v >= u) {
		WS_Release(ctx->ws, 0);
		VSLb(ctx->vsl, SLT_Error,
		    "vsf.urldecode: Out of workspace (%u/%u)",
		    v, u);
		return (NULL);
	} else {
		WS_Release(ctx->ws, v + 1);
		return (p);
	}
}

void
vmod_conn_reset(VRT_CTX)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (ctx->method != VCL_MET_RECV) {
		VSLb(ctx->vsl, SLT_Error,
		    "vsf.conn_reset: Can only be called from vcl_recv{}");
		return;
	}
	if (ctx->req->sp->fd < 0) {
		VSLb(ctx->vsl, SLT_Error,
		    "vsf.conn_reset: Invalid file descriptor");
		return;
	}
	ctx->req->restarts = cache_param->max_restarts;
	VTCP_linger(ctx->req->sp->fd, 1);
	SES_Close(ctx->req->sp, SC_NULL);
}
