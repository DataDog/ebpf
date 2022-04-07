package perf

import (
	"sync"
	"sync/atomic"
)

// DISCLAIMER: We should favor a completely different API for potentially
// merging this idea of buffered reads into upstream (like adding a `ReadInto` method
// to ` perf.Reader`).
//
// This is just the easiest way I found to PoC this without changing much both datadog-agent and the ebpf.Manager code.
//
// Here the readPool will automatically "activated" if the client code calls `Reclaim` on `perf.Record`,
// otherwise the only impact is an extra atomic operation.
type readPool struct {
	active     int64
	bufferSize int
	pool       *sync.Pool
}

type readBuffer struct {
	origin *readPool
	bptr   *[]byte // required by sync.Pool. nil in case the buffer is not reusable
	data   []byte
}

func newReadPool(size int) *readPool {
	return &readPool{
		bufferSize: size,
		pool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

func (p *readPool) GetBuffer(size int) readBuffer {
	// don't used pooled buffers in case the client isn't using the callback API
	// or in case we have a read that can't be fit into a normal-sized buffer
	if p == nil || size > p.bufferSize || atomic.LoadInt64(&p.active) == 0 {
		return readBuffer{
			origin: p,
			data:   make([]byte, size),
		}
	}

	bptr := p.pool.Get().(*[]byte)
	data := *bptr
	return readBuffer{
		origin: p,
		bptr:   bptr,
		data:   data[:size],
	}
}

func (b *readBuffer) Reclaim() {
	if b == nil || b.origin == nil {
		return
	}

	atomic.StoreInt64(&b.origin.active, 1)
	if b.bptr != nil {
		b.origin.pool.Put(b.bptr)
	}
}
