package tls

import (
	"runtime"
	"unsafe"
)

// #include "shim.h"
import "C"

var (
	ssl_ctx_idx = C.X_SSL_CTX_new_index()
)

//export get_ssl_ctx_idx
func get_ssl_ctx_idx() C.int {
	return ssl_ctx_idx
}

type ssl_ctx struct {
	ctx *C.SSL_CTX
}

func newCtx(method *C.SSL_METHOD) (*ssl_ctx, error) {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ctx := C.SSL_CTX_new(method)
	if ctx == nil {
		return nil, errorFromErrorQueue()
	}

	c := &ssl_ctx{ctx: ctx}
	C.SSL_CTX_set_ex_data(ctx, get_ssl_ctx_idx(), unsafe.Pointer(c))

	runtime.SetFinalizer(c, func(c *ssl_ctx) {
		C.SSL_CTX_free(c.ctx)
	})

	return c, nil
}

type Modes int

const (
	// ReleaseBuffers is only valid if you are using OpenSSL 1.0.1 or newer
	ReleaseBuffers Modes = C.SSL_MODE_RELEASE_BUFFERS
)

// SetMode sets context modes. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
func (c *ssl_ctx) SetMode(modes Modes) Modes {
	return Modes(C.X_SSL_CTX_set_mode(c.ctx, C.long(modes)))
}

// GetMode returns context modes. See
// http://www.openssl.org/docs/ssl/SSL_CTX_set_mode.html
func (c *ssl_ctx) GetMode() Modes {
	return Modes(C.X_SSL_CTX_get_mode(c.ctx))
}
