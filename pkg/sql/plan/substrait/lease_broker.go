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

package substrait

import (
	"sync"
	"time"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
)

type leaseManagerBrokerState uint8

const (
	leaseManagerBrokerEmpty leaseManagerBrokerState = iota
	leaseManagerBrokerPreparing
	leaseManagerBrokerPublished
	leaseManagerBrokerSealed
)

// LeaseManagerBroker transfers ownership of exactly one replayed, co-located
// TAE lease-manager generation from TN construction to the embedded CN. It is
// deliberately not a replacement registry: observing a second live storage
// generation seals the broker so callers fail closed instead of silently
// switching the GC-protection authority beneath an active CN.
//
// A broker belongs to one process launch. It has no Reset operation. The
// launcher must create a new broker for a new process generation and must seal
// the old broker before tearing down the TAE protection owner.
type LeaseManagerBroker struct {
	mu                 sync.RWMutex
	state              leaseManagerBrokerState
	generation         uint64
	identity           string
	manager            *LeaseManager
	teardownAllowed    bool
	topologyGeneration uint64
	topologyValidUntil time.Time
	now                func() time.Time
}

// LeaseManagerCapability is the revocable proof that one CN generation still
// refers to the exact TAE storage generation published by its launcher. It is
// retained by the CN runtime and checked at lookup and embedded admission; a
// pointer to a manager alone is intentionally not proof that its storage owner
// is still the live co-located authority.
type LeaseManagerCapability struct {
	broker             *LeaseManagerBroker
	generation         uint64
	identity           string
	manager            *LeaseManager
	topologyGeneration uint64
}

// LeaseManagerCapabilityHandoff renews one already-attested topology lease
// while launcher-owned CN construction and replay are in progress. Ownership
// transfers to the service monitor only after that monitor has validated the
// topology and registered its task.
type LeaseManagerCapabilityHandoff struct {
	capability *LeaseManagerCapability
	validFor   time.Duration
	interval   time.Duration
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
}

// LeaseManagerPublication is a prepare token. Publish is valid only after the
// complete TAE storage (including its logtail server) has been constructed.
// Abort removes an unpublished preparation after storage-open failure.
type LeaseManagerPublication struct {
	broker     *LeaseManagerBroker
	generation uint64
	identity   string
	manager    *LeaseManager
	mu         sync.Mutex
	done       bool
}

func NewLeaseManagerBroker() *LeaseManagerBroker {
	return &LeaseManagerBroker{now: time.Now}
}

// Prepare reserves the broker for manager without making it acquirable.
func (b *LeaseManagerBroker) Prepare(
	storageIdentity string,
	manager *LeaseManager,
) (*LeaseManagerPublication, error) {
	if b == nil || storageIdentity == "" || manager == nil || !manager.DurableReady() {
		return nil, moerr.NewInternalErrorNoCtx("substrait: invalid lease manager publication")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case leaseManagerBrokerEmpty:
		b.generation++
		b.state = leaseManagerBrokerPreparing
		b.identity = storageIdentity
		b.manager = manager
		b.teardownAllowed = false
		b.topologyValidUntil = time.Time{}
		return &LeaseManagerPublication{
			broker: b, generation: b.generation,
			identity: storageIdentity, manager: manager,
		}, nil
	case leaseManagerBrokerPreparing, leaseManagerBrokerPublished:
		// A concurrent or replacement storage generation invalidates the whole
		// single-generation handoff. Keep the manager's protection alive, but
		// make it impossible for a CN to acquire either ambiguous generation.
		b.state = leaseManagerBrokerSealed
		b.manager = nil
		b.teardownAllowed = false
		b.topologyValidUntil = time.Time{}
		return nil, moerr.NewInvalidStateNoCtx("substrait: a second TAE lease manager generation is not supported")
	case leaseManagerBrokerSealed:
		return nil, moerr.NewInvalidStateNoCtx("substrait: TAE lease manager broker is sealed")
	default:
		return nil, moerr.NewInternalErrorNoCtx("substrait: invalid lease manager broker state")
	}
}

// Publish is the linearization point at which later CN injection may acquire
// the manager. It never replaces an existing publication.
func (p *LeaseManagerPublication) Publish() error {
	if p == nil || p.broker == nil {
		return moerr.NewInternalErrorNoCtx("substrait: invalid lease manager publication token")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return moerr.NewInvalidStateNoCtx("substrait: lease manager publication token is already terminal")
	}
	b := p.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != leaseManagerBrokerPreparing || b.generation != p.generation ||
		b.identity != p.identity || b.manager != p.manager {
		p.done = true
		return moerr.NewInvalidStateNoCtx("substrait: lease manager publication was superseded")
	}
	b.state = leaseManagerBrokerPublished
	p.done = true
	return nil
}

// Abort forgets only this unpublished preparation. It never clears a
// published manager or unprotects its recovered leases.
func (p *LeaseManagerPublication) Abort() error {
	if p == nil || p.broker == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return nil
	}
	b := p.broker
	b.mu.Lock()
	if b.state == leaseManagerBrokerPreparing && b.generation == p.generation &&
		b.identity == p.identity && b.manager == p.manager {
		b.state = leaseManagerBrokerEmpty
		b.identity = ""
		b.manager = nil
	}
	b.mu.Unlock()
	p.done = true
	return nil
}

// Acquire returns the one published manager and its shard-stable storage
// identity. An acquired pointer remains owned by the process generation; the
// broker does not provide a release operation that could remove GC protection.
func (b *LeaseManagerBroker) Acquire() (*LeaseManager, string, error) {
	manager, identity, _, err := b.AcquireCapability()
	return manager, identity, err
}

// AcquireCapability returns the published manager together with revocable
// generation proof. Callers that retain the manager beyond startup must retain
// and check the capability as well.
func (b *LeaseManagerBroker) AcquireCapability() (
	*LeaseManager,
	string,
	*LeaseManagerCapability,
	error,
) {
	if b == nil {
		return nil, "", nil, moerr.NewInvalidStateNoCtx("substrait: TAE lease manager broker is unavailable")
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	switch b.state {
	case leaseManagerBrokerPublished:
		return b.manager, b.identity, &LeaseManagerCapability{
			broker: b, generation: b.generation, identity: b.identity, manager: b.manager,
			topologyGeneration: b.topologyGeneration,
		}, nil
	case leaseManagerBrokerSealed:
		return nil, "", nil, moerr.NewInvalidStateNoCtx("substrait: TAE lease manager broker is sealed")
	default:
		return nil, "", nil, moerr.NewInvalidStateNoCtx("substrait: TAE lease manager is not published")
	}
}

// AttestTopology records a bounded lease over the authoritative live topology
// and returns capability proof for that topology generation. The CN must renew
// it from HAKeeper; expiry fails closed even if no source-removal command was
// delivered locally.
func (b *LeaseManagerBroker) AttestTopology(
	storageIdentity string,
	validFor time.Duration,
) (*LeaseManagerCapability, error) {
	if b == nil || storageIdentity == "" || validFor <= 0 {
		return nil, moerr.NewBadConfigNoCtx("invalid Sirius topology attestation")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != leaseManagerBrokerPublished || b.identity != storageIdentity || b.manager == nil {
		return nil, moerr.NewInvalidStateNoCtx("substrait: cannot attest an unpublished TAE topology")
	}
	if b.now == nil {
		return nil, moerr.NewInternalErrorNoCtx("substrait: topology fence clock is unavailable")
	}
	if b.topologyGeneration != 0 {
		return nil, moerr.NewInvalidStateNoCtx("substrait: TAE topology generation is already attested")
	}
	b.topologyGeneration = 1
	b.topologyValidUntil = b.now().Add(validFor)
	return &LeaseManagerCapability{
		broker: b, generation: b.generation, identity: b.identity, manager: b.manager,
		topologyGeneration: b.topologyGeneration,
	}, nil
}

// StorageIdentity returns the immutable shard-stable identity covered by this
// generation. It contains no object path or tenant data.
func (c *LeaseManagerCapability) StorageIdentity() string {
	if c == nil {
		return ""
	}
	return c.identity
}

// Healthy fails after any broker revocation, replacement attempt, or launcher
// seal. Existing query owners keep their manager/protection pointer, but no new
// query may treat that pointer as current topology authority.
func (c *LeaseManagerCapability) Healthy() error {
	if c == nil || c.broker == nil || c.manager == nil || c.identity == "" {
		return moerr.NewInvalidStateNoCtx("substrait: TAE lease manager capability is unavailable")
	}
	b := c.broker
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.state != leaseManagerBrokerPublished || b.generation != c.generation ||
		b.identity != c.identity || b.manager != c.manager ||
		c.topologyGeneration == 0 || b.topologyGeneration != c.topologyGeneration ||
		b.now == nil || !b.now().Before(b.topologyValidUntil) {
		return moerr.NewInvalidStateNoCtx("substrait: TAE lease manager capability is revoked")
	}
	return nil
}

// RenewTopology extends this capability's bounded HAKeeper attestation without
// changing its generation. A stale or revoked capability cannot renew itself.
func (c *LeaseManagerCapability) RenewTopology(validFor time.Duration) error {
	if c == nil || c.broker == nil || validFor <= 0 {
		return moerr.NewInvalidStateNoCtx("substrait: invalid topology fence renewal")
	}
	b := c.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != leaseManagerBrokerPublished || b.generation != c.generation ||
		b.identity != c.identity || b.manager != c.manager ||
		c.topologyGeneration == 0 || b.topologyGeneration != c.topologyGeneration || b.now == nil ||
		!b.now().Before(b.topologyValidUntil) {
		return moerr.NewInvalidStateNoCtx("substrait: TAE lease manager capability is revoked")
	}
	b.topologyValidUntil = b.now().Add(validFor)
	return nil
}

// RevokeTopology invalidates this generation without authorizing storage
// teardown. The old protection owner remains live until the CN drains and the
// launcher calls Seal.
func (c *LeaseManagerCapability) RevokeTopology() {
	if c == nil || c.broker == nil {
		return
	}
	b := c.broker
	b.mu.Lock()
	if b.generation == c.generation && b.identity == c.identity &&
		b.topologyGeneration == c.topologyGeneration {
		b.state = leaseManagerBrokerSealed
		b.manager = nil
		b.teardownAllowed = false
		b.topologyValidUntil = time.Time{}
	}
	b.mu.Unlock()
}

// StartTopologyRenewalHandoff starts bounded renewal immediately after initial
// HAKeeper attestation. It does not validate topology itself; the launcher and
// accepting service monitor own those validations on either side of handoff.
func StartTopologyRenewalHandoff(
	capability *LeaseManagerCapability,
	validFor time.Duration,
	interval time.Duration,
) (*LeaseManagerCapabilityHandoff, error) {
	if capability == nil || validFor <= 0 || interval <= 0 || interval >= validFor {
		return nil, moerr.NewBadConfigNoCtx("invalid Sirius topology renewal handoff")
	}
	if err := capability.Healthy(); err != nil {
		return nil, err
	}
	h := &LeaseManagerCapabilityHandoff{
		capability: capability, validFor: validFor, interval: interval,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go h.run()
	return h, nil
}

func (h *LeaseManagerCapabilityHandoff) run() {
	defer close(h.done)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			if err := h.renew(); err != nil {
				return
			}
		}
	}
}

func (h *LeaseManagerCapabilityHandoff) renew() error {
	if h == nil || h.capability == nil {
		return moerr.NewInvalidStateNoCtx("substrait: topology renewal handoff is unavailable")
	}
	return h.capability.RenewTopology(h.validFor)
}

// Stop joins the launcher renewal owner. It is idempotent.
func (h *LeaseManagerCapabilityHandoff) Stop() {
	if h == nil {
		return
	}
	h.stopOnce.Do(func() { close(h.stop) })
	<-h.done
}

// HealthyFor additionally proves that manager is the exact manager published
// with this generation. Embedded TAE and local Flight use it to prevent a
// valid topology token from blessing unrelated lease state.
func (c *LeaseManagerCapability) HealthyFor(manager *LeaseManager) error {
	if err := c.Healthy(); err != nil {
		return err
	}
	if manager == nil || c.manager != manager {
		return moerr.NewInvalidStateNoCtx("substrait: TAE lease manager capability does not match the runtime manager")
	}
	return nil
}

// RevokeStorage is called before an explicit-broker TN removes storage. It
// revokes CN admission first and returns true while teardown must be refused.
// Only a later launcher Seal, after CN drain, authorizes orderly teardown.
func (b *LeaseManagerBroker) RevokeStorage(storageIdentity string) (bool, error) {
	if b == nil || storageIdentity == "" {
		return false, moerr.NewInternalErrorNoCtx("substrait: invalid TAE storage revocation")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.identity != storageIdentity {
		return false, nil
	}
	switch b.state {
	case leaseManagerBrokerPreparing, leaseManagerBrokerPublished:
		b.state = leaseManagerBrokerSealed
		b.manager = nil
		b.teardownAllowed = false
		b.topologyValidUntil = time.Time{}
		return true, nil
	case leaseManagerBrokerSealed:
		return !b.teardownAllowed, nil
	case leaseManagerBrokerEmpty:
		return false, nil
	default:
		return true, moerr.NewInternalErrorNoCtx("substrait: invalid lease manager broker state")
	}
}

// Seal prevents future publication or acquisition. It intentionally does not
// release a manager or its GC protections; the launcher owns CN drain followed
// by TAE shutdown ordering.
func (b *LeaseManagerBroker) Seal() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.state = leaseManagerBrokerSealed
	b.manager = nil
	b.teardownAllowed = true
	b.topologyValidUntil = time.Time{}
	b.mu.Unlock()
}
