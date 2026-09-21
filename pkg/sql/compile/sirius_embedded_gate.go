// Copyright 2026 Matrix Origin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compile

import (
	"container/list"
	"context"
	"sync"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
)

const (
	defaultSiriusEmbeddedMaxWaiting uint32 = 16
	maxSiriusEmbeddedMaxWaiting     uint32 = 16
)

// siriusEmbeddedAdmissionGate serializes embedded queries before they open a
// relation, reserve storage protection, or enter the native backend. Waiters
// are retained in an intrusive FIFO so cancellation removes one waiter in O(1)
// without a helper goroutine.
type siriusEmbeddedAdmissionGate struct {
	mu         sync.Mutex
	active     bool
	sealed     bool
	maxWaiting int
	waiters    list.List
}

type siriusEmbeddedAdmissionWaiter struct {
	ready   chan struct{}
	element *list.Element
	granted bool
	err     error
}

// siriusEmbeddedAdmissionPermit owns the single active slot. Release is
// deliberately idempotent because Compile release and execution cleanup can
// converge on the same query owner.
type siriusEmbeddedAdmissionPermit struct {
	gate *siriusEmbeddedAdmissionGate
	once sync.Once
}

func newSiriusEmbeddedAdmissionGate(maxWaiting uint32) (*siriusEmbeddedAdmissionGate, error) {
	if maxWaiting == 0 {
		maxWaiting = defaultSiriusEmbeddedMaxWaiting
	}
	if maxWaiting > maxSiriusEmbeddedMaxWaiting {
		return nil, moerr.NewBadConfigNoCtxf(
			"Sirius embedded admission permits at most %d waiting queries",
			maxSiriusEmbeddedMaxWaiting,
		)
	}
	return &siriusEmbeddedAdmissionGate{maxWaiting: int(maxWaiting)}, nil
}

func (r *SiriusRuntime) acquireEmbeddedAdmission(
	ctx context.Context,
) (*siriusEmbeddedAdmissionPermit, error) {
	if r == nil || r.embeddedAdmission == nil {
		return nil, moerr.NewInvalidStateNoCtx(
			"substrait: embedded Sirius admission is uninitialized")
	}
	return r.embeddedAdmission.acquire(ctx)
}

func (g *siriusEmbeddedAdmissionGate) acquire(ctx context.Context) (*siriusEmbeddedAdmissionPermit, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}

	g.mu.Lock()
	if g.sealed {
		g.mu.Unlock()
		return nil, moerr.NewInvalidStateNoCtx("substrait: embedded Sirius admission is sealed")
	}
	if !g.active {
		g.active = true
		g.mu.Unlock()
		return &siriusEmbeddedAdmissionPermit{gate: g}, nil
	}
	if g.waiters.Len() >= g.maxWaiting {
		g.mu.Unlock()
		return nil, moerr.NewInvalidStateNoCtx("substrait: embedded Sirius admission queue is full")
	}
	waiter := &siriusEmbeddedAdmissionWaiter{ready: make(chan struct{})}
	waiter.element = g.waiters.PushBack(waiter)
	g.mu.Unlock()

	select {
	case <-waiter.ready:
		if waiter.err != nil {
			return nil, waiter.err
		}
		permit := &siriusEmbeddedAdmissionPermit{gate: g}
		if err := context.Cause(ctx); err != nil {
			permit.release()
			return nil, err
		}
		return permit, nil
	case <-ctx.Done():
		g.mu.Lock()
		if waiter.granted {
			g.mu.Unlock()
			// Cancellation won the caller-facing race after the FIFO handoff.
			// Forward the slot instead of starting storage for a canceled query.
			(&siriusEmbeddedAdmissionPermit{gate: g}).release()
			return nil, context.Cause(ctx)
		}
		if waiter.element != nil {
			g.waiters.Remove(waiter.element)
			waiter.element = nil
		}
		g.mu.Unlock()
		return nil, context.Cause(ctx)
	}
}

func (p *siriusEmbeddedAdmissionPermit) release() {
	if p == nil || p.gate == nil {
		return
	}
	p.once.Do(p.gate.release)
}

func (g *siriusEmbeddedAdmissionGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.active {
		return
	}
	if g.sealed || g.waiters.Len() == 0 {
		g.active = false
		return
	}
	element := g.waiters.Front()
	waiter := element.Value.(*siriusEmbeddedAdmissionWaiter)
	g.waiters.Remove(element)
	waiter.element = nil
	waiter.granted = true
	// active deliberately remains true: ownership moves directly to the FIFO
	// head, leaving no interval in which a later caller can overtake it.
	close(waiter.ready)
}

func (g *siriusEmbeddedAdmissionGate) seal() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return
	}
	g.sealed = true
	for element := g.waiters.Front(); element != nil; {
		next := element.Next()
		waiter := element.Value.(*siriusEmbeddedAdmissionWaiter)
		g.waiters.Remove(element)
		waiter.element = nil
		waiter.err = moerr.NewInvalidStateNoCtx("substrait: embedded Sirius admission is sealed")
		close(waiter.ready)
		element = next
	}
}

func (g *siriusEmbeddedAdmissionGate) accepting() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.sealed
}
