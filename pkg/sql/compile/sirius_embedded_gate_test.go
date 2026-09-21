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
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matrixorigin/matrixone/pkg/common/mpool"
	"github.com/matrixorigin/matrixone/pkg/container/batch"
	"github.com/matrixorigin/matrixone/pkg/perfcounter"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func waitForSiriusGateWaiters(t *testing.T, gate *siriusEmbeddedAdmissionGate, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		gate.mu.Lock()
		got := gate.waiters.Len()
		gate.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Sirius gate has %d waiters, want %d", got, want)
		}
		runtime.Gosched()
	}
}

func receiveSiriusGateResult[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Sirius gate transition")
		var zero T
		return zero
	}
}

func TestSiriusEmbeddedAdmissionBoundAndFIFO(t *testing.T) {
	gate, err := newSiriusEmbeddedAdmissionGate(16)
	require.NoError(t, err)
	active, err := gate.acquire(context.Background())
	require.NoError(t, err)

	type admitted struct {
		index  int
		permit *siriusEmbeddedAdmissionPermit
		err    error
	}
	entered := make(chan admitted, 16)
	done := make(chan struct{}, 16)
	release := make([]chan struct{}, 16)
	var relationCalls atomic.Int32
	var storageCalls atomic.Int32
	var backendCalls atomic.Int32
	var inside atomic.Int32
	var maximum atomic.Int32
	for i := range release {
		release[i] = make(chan struct{})
		go func(index int) {
			permit, acquireErr := gate.acquire(context.Background())
			if acquireErr != nil {
				entered <- admitted{index: index, err: acquireErr}
				return
			}
			relationCalls.Add(1)
			storageCalls.Add(1)
			backendCalls.Add(1)
			concurrent := inside.Add(1)
			for previous := maximum.Load(); concurrent > previous && !maximum.CompareAndSwap(previous, concurrent); {
				previous = maximum.Load()
			}
			entered <- admitted{index: index, permit: permit}
			<-release[index]
			inside.Add(-1)
			permit.release()
			done <- struct{}{}
		}(i)
		waitForSiriusGateWaiters(t, gate, i+1)
	}
	require.Zero(t, relationCalls.Load())
	require.Zero(t, storageCalls.Load())
	require.Zero(t, backendCalls.Load())

	_, err = gate.acquire(context.Background())
	require.ErrorContains(t, err, "queue is full")
	require.Zero(t, relationCalls.Load(), "a full rejection must not enter relation setup")
	require.Zero(t, storageCalls.Load(), "a full rejection must not enter storage admission")
	require.Zero(t, backendCalls.Load(), "a full rejection must not enter native Prepare")

	active.release()
	for i := range release {
		got := receiveSiriusGateResult(t, entered)
		require.Equal(t, i, got.index, "handoff must preserve enqueue order")
		require.NoError(t, got.err)
		require.Equal(t, int32(1), inside.Load(), "exactly one query owns the gate")
		close(release[i])
		receiveSiriusGateResult(t, done)
	}
	require.Equal(t, int32(1), maximum.Load())
	require.Equal(t, int32(16), backendCalls.Load())
}

func TestSiriusEmbeddedAdmissionCancellationRemovesMiddleWaiter(t *testing.T) {
	gate, err := newSiriusEmbeddedAdmissionGate(3)
	require.NoError(t, err)
	active, err := gate.acquire(context.Background())
	require.NoError(t, err)

	type result struct {
		index  int
		permit *siriusEmbeddedAdmissionPermit
		err    error
	}
	results := make(chan result, 3)
	contexts := make([]context.Context, 3)
	cancels := make([]context.CancelFunc, 3)
	for i := range contexts {
		contexts[i], cancels[i] = context.WithCancel(context.Background())
		go func(index int) {
			permit, acquireErr := gate.acquire(contexts[index])
			results <- result{index: index, permit: permit, err: acquireErr}
		}(i)
		waitForSiriusGateWaiters(t, gate, i+1)
	}
	t.Cleanup(func() {
		for _, cancel := range cancels {
			cancel()
		}
	})

	cancels[1]()
	canceled := receiveSiriusGateResult(t, results)
	require.Equal(t, 1, canceled.index)
	require.ErrorIs(t, canceled.err, context.Canceled)
	waitForSiriusGateWaiters(t, gate, 2)

	active.release()
	first := receiveSiriusGateResult(t, results)
	require.Equal(t, 0, first.index)
	require.NoError(t, first.err)
	first.permit.release()
	third := receiveSiriusGateResult(t, results)
	require.Equal(t, 2, third.index, "cancellation must not strand the next FIFO waiter")
	require.NoError(t, third.err)
	third.permit.release()
}

func TestSiriusEmbeddedAdmissionCanceledHandoffForwardsPermit(t *testing.T) {
	gate, err := newSiriusEmbeddedAdmissionGate(1)
	require.NoError(t, err)
	active, err := gate.acquire(context.Background())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		permit, acquireErr := gate.acquire(ctx)
		if permit != nil {
			permit.release()
		}
		result <- acquireErr
	}()
	waitForSiriusGateWaiters(t, gate, 1)

	// Publish cancellation and FIFO handoff under the same gate critical
	// section, making both select cases ready before the waiter can observe
	// either. Whichever select arm wins, no canceled query may retain the slot.
	gate.mu.Lock()
	cancel()
	element := gate.waiters.Front()
	waiter := element.Value.(*siriusEmbeddedAdmissionWaiter)
	gate.waiters.Remove(element)
	waiter.element = nil
	waiter.granted = true
	close(waiter.ready)
	gate.mu.Unlock()
	require.ErrorIs(t, receiveSiriusGateResult(t, result), context.Canceled)

	gate.mu.Lock()
	require.False(t, gate.active, "canceled handoff must forward the active slot")
	gate.mu.Unlock()
	active.release()
}

func TestSiriusRuntimeCloseSealsBeforeBackendClose(t *testing.T) {
	backendStarted := make(chan struct{})
	allowBackendClose := make(chan struct{})
	backend := &siriusEmbeddedBackendStub{close: func(context.Context) error {
		close(backendStarted)
		<-allowBackendClose
		return nil
	}}
	siriusRuntime := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, Backend: backend, CleanupTimeout: time.Second,
	}
	require.NoError(t, siriusRuntime.InitEmbeddedAdmission(3))
	active, err := siriusRuntime.acquireEmbeddedAdmission(context.Background())
	require.NoError(t, err)

	waiters := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, acquireErr := siriusRuntime.acquireEmbeddedAdmission(context.Background())
			waiters <- acquireErr
		}()
		waitForSiriusGateWaiters(t, siriusRuntime.embeddedAdmission, i+1)
	}
	closed := make(chan error, 1)
	go func() { closed <- siriusRuntime.Close(context.Background()) }()
	receiveSiriusGateResult(t, backendStarted)
	for range 3 {
		require.ErrorContains(t, receiveSiriusGateResult(t, waiters), "admission is sealed")
	}
	_, err = siriusRuntime.acquireEmbeddedAdmission(context.Background())
	require.ErrorContains(t, err, "admission is sealed")
	close(allowBackendClose)
	require.NoError(t, receiveSiriusGateResult(t, closed))
	active.release()
}

type siriusSealingPrepareBackend struct {
	accepting atomic.Bool
	started   chan struct{}
	proceed   chan struct{}
	nilResult bool
}

func (b *siriusSealingPrepareBackend) Prepare(context.Context, SiriusPrepareRequest) (SiriusExecution, error) {
	close(b.started)
	<-b.proceed
	b.accepting.Store(false)
	if b.nilResult {
		return nil, nil
	}
	return nil, errors.New("native cleanup failed")
}

func (*siriusSealingPrepareBackend) Reconcile(uint64, []byte, func(context.Context) error) error {
	return nil
}
func (*siriusSealingPrepareBackend) Close(context.Context) error { return nil }
func (*siriusSealingPrepareBackend) CanFallbackBeforeVisibility(error) bool {
	return false
}
func (b *siriusSealingPrepareBackend) Accepting() bool { return b.accepting.Load() }

func TestSiriusEmbeddedPrepareFailureSealsBeforePermitHandoff(t *testing.T) {
	for _, nilResult := range []bool{false, true} {
		t.Run(map[bool]string{false: "backend sealed on error", true: "nil success"}[nilResult], func(t *testing.T) {
			backend := &siriusSealingPrepareBackend{
				started: make(chan struct{}), proceed: make(chan struct{}), nilResult: nilResult,
			}
			backend.accepting.Store(true)
			siriusRuntime := &SiriusRuntime{
				Source: SiriusRuntimeEmbeddedMO, Backend: backend, CleanupTimeout: time.Second,
			}
			require.NoError(t, siriusRuntime.InitEmbeddedAdmission(1))
			active, err := siriusRuntime.acquireEmbeddedAdmission(context.Background())
			require.NoError(t, err)

			var downstreamCalls atomic.Int32
			waiter := make(chan error, 1)
			go func() {
				permit, acquireErr := siriusRuntime.acquireEmbeddedAdmission(context.Background())
				if permit != nil {
					downstreamCalls.Add(1)
					permit.release()
				}
				waiter <- acquireErr
			}()
			waitForSiriusGateWaiters(t, siriusRuntime.embeddedAdmission, 1)

			prepared := make(chan error, 1)
			go func() {
				_, prepareErr := siriusRuntime.prepareEmbeddedExecution(
					context.Background(), SiriusPrepareRequest{})
				// This is the compile path's deferred pre-transfer release.
				active.release()
				prepared <- prepareErr
			}()
			receiveSiriusGateResult(t, backend.started)
			close(backend.proceed)
			require.Error(t, receiveSiriusGateResult(t, prepared))
			require.ErrorContains(t, receiveSiriusGateResult(t, waiter), "admission is sealed")
			require.Zero(t, downstreamCalls.Load(), "a queued query must not pass a poisoned backend")
		})
	}
}

func TestSiriusEmbeddedRunReleasesOrSealsAdmission(t *testing.T) {
	tests := []struct {
		name           string
		run            func() error
		cleanup        func(context.Context) error
		wantRunError   string
		wantPanic      bool
		wantGateSealed bool
		cleanupRetries bool
	}{
		{name: "success", run: func() error { return nil }, cleanup: func(context.Context) error { return nil }},
		{name: "run error", run: func() error { return errors.New("run failed") }, cleanup: func(context.Context) error { return nil }, wantRunError: "run failed"},
		{name: "run panic", run: func() error { panic("run panic") }, cleanup: func(context.Context) error { return nil }, wantPanic: true},
		{name: "cleanup failure", run: func() error { return nil }, cleanup: func(context.Context) error { return errors.New("cleanup failed") }, wantRunError: "cleanup failed", wantGateSealed: true, cleanupRetries: true},
		{name: "cleanup timeout", run: func() error { return nil }, cleanup: func(ctx context.Context) error { <-ctx.Done(); return context.Cause(ctx) }, wantRunError: "timed out cleaning up", wantGateSealed: true, cleanupRetries: true},
		{name: "cleanup panic", run: func() error { return nil }, cleanup: func(context.Context) error { panic("cleanup panic") }, wantRunError: "panic cleaning up", wantGateSealed: true, cleanupRetries: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proc := testutil.NewProcess(t)
			t.Cleanup(proc.Free)
			cleanupTimeout := time.Second
			if test.name == "cleanup timeout" {
				cleanupTimeout = 10 * time.Millisecond
			}
			siriusRuntime := &SiriusRuntime{
				Source: SiriusRuntimeEmbeddedMO, CleanupTimeout: cleanupTimeout,
			}
			require.NoError(t, siriusRuntime.InitEmbeddedAdmission(1))
			permit, err := siriusRuntime.acquireEmbeddedAdmission(context.Background())
			require.NoError(t, err)
			var cleanups atomic.Int32
			execution := &siriusExecutionStub{
				run: func(context.Context, *mpool.MPool, *perfcounter.CounterSet, func(*batch.Batch, *perfcounter.CounterSet) error) error {
					return test.run()
				},
				cleanup: func(ctx context.Context, _ bool) error {
					attempt := cleanups.Add(1)
					if test.cleanupRetries && attempt > 1 {
						return nil
					}
					return test.cleanup(ctx)
				},
			}
			owner := newSiriusEmbeddedReadOwner(execution, siriusRuntime, permit)
			c := allocateNewCompile(proc)
			c.siriusRead = owner

			waiter := make(chan error, 1)
			go func() {
				next, acquireErr := siriusRuntime.acquireEmbeddedAdmission(context.Background())
				if next != nil {
					next.release()
				}
				waiter <- acquireErr
			}()
			waitForSiriusGateWaiters(t, siriusRuntime.embeddedAdmission, 1)

			var runErr error
			if test.wantPanic {
				require.PanicsWithValue(t, "run panic", func() {
					_ = c.runSiriusRead(context.Background(), nil)
				})
			} else {
				runErr = c.runSiriusRead(context.Background(), nil)
				if test.wantRunError == "" {
					require.NoError(t, runErr)
				} else {
					require.ErrorContains(t, runErr, test.wantRunError)
				}
			}
			waiterErr := receiveSiriusGateResult(t, waiter)
			if test.wantGateSealed {
				require.ErrorContains(t, waiterErr, "admission is sealed")
			} else {
				require.NoError(t, waiterErr)
			}
			require.Equal(t, int32(1), cleanups.Load())
			c.Release()
			wantCleanups := int32(1)
			if test.cleanupRetries {
				wantCleanups = 2
			}
			require.Equal(t, wantCleanups, cleanups.Load(),
				"failed cleanup must remain retryable while successful cleanup stays terminal")
		})
	}
}

func TestSiriusReadOwnerConcurrentCleanupWaitHonorsContext(t *testing.T) {
	siriusRuntime := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, CleanupTimeout: time.Second,
	}
	require.NoError(t, siriusRuntime.InitEmbeddedAdmission(1))
	permit, err := siriusRuntime.acquireEmbeddedAdmission(context.Background())
	require.NoError(t, err)
	cleanupStarted := make(chan struct{})
	allowCleanup := make(chan struct{})
	var cleanups atomic.Int32
	execution := &siriusExecutionStub{
		run: func(context.Context, *mpool.MPool, *perfcounter.CounterSet, func(*batch.Batch, *perfcounter.CounterSet) error) error {
			return nil
		},
		cleanup: func(context.Context, bool) error {
			cleanups.Add(1)
			close(cleanupStarted)
			<-allowCleanup
			return nil
		},
	}
	owner := newSiriusEmbeddedReadOwner(execution, siriusRuntime, permit)
	first := make(chan error, 1)
	go func() { first <- owner.finish(context.Background(), false) }()
	receiveSiriusGateResult(t, cleanupStarted)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, owner.finish(canceled, false), context.Canceled)
	require.Equal(t, int32(1), cleanups.Load(), "a concurrent waiter must not start another attempt")
	close(allowCleanup)
	require.NoError(t, receiveSiriusGateResult(t, first))
	require.NoError(t, owner.finish(context.Background(), false))
	require.Equal(t, int32(1), cleanups.Load(), "successful cleanup is terminal")
}

type siriusObservedDoneContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *siriusObservedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func TestSiriusReadOwnerFailureSealsBeforeConcurrentRetry(t *testing.T) {
	siriusRuntime := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, CleanupTimeout: time.Second,
	}
	require.NoError(t, siriusRuntime.InitEmbeddedAdmission(1))
	permit, err := siriusRuntime.acquireEmbeddedAdmission(context.Background())
	require.NoError(t, err)

	var storageStarts atomic.Int32
	admission := make(chan error, 1)
	go func() {
		next, acquireErr := siriusRuntime.acquireEmbeddedAdmission(context.Background())
		if next != nil {
			storageStarts.Add(1)
			next.release()
		}
		admission <- acquireErr
	}()
	waitForSiriusGateWaiters(t, siriusRuntime.embeddedAdmission, 1)

	firstCleanupStarted := make(chan struct{})
	failFirstCleanup := make(chan struct{})
	retrySawSealed := make(chan bool, 1)
	var cleanupAttempts atomic.Int32
	execution := &siriusExecutionStub{
		run: func(context.Context, *mpool.MPool, *perfcounter.CounterSet, func(*batch.Batch, *perfcounter.CounterSet) error) error {
			return nil
		},
		cleanup: func(context.Context, bool) error {
			switch cleanupAttempts.Add(1) {
			case 1:
				close(firstCleanupStarted)
				<-failFirstCleanup
				return errors.New("first cleanup failed")
			case 2:
				retrySawSealed <- !siriusRuntime.embeddedAdmission.accepting()
				return nil
			default:
				return errors.New("unexpected cleanup attempt")
			}
		},
	}
	owner := newSiriusEmbeddedReadOwner(execution, siriusRuntime, permit)
	first := make(chan error, 1)
	go func() { first <- owner.finish(context.Background(), false) }()
	receiveSiriusGateResult(t, firstCleanupStarted)

	// Done() is evaluated only after the competing finish caller observes the
	// active attempt and enters its cancellation-aware wait. This is a phase
	// barrier, not a scheduling delay.
	secondWaiting := make(chan struct{})
	secondCtx := &siriusObservedDoneContext{
		Context: context.Background(), observed: secondWaiting,
	}
	second := make(chan error, 1)
	go func() { second <- owner.finish(secondCtx, false) }()
	receiveSiriusGateResult(t, secondWaiting)
	close(failFirstCleanup)

	require.ErrorContains(t, receiveSiriusGateResult(t, first), "first cleanup failed")
	require.True(t, receiveSiriusGateResult(t, retrySawSealed),
		"failed cleanup must poison admission before publishing cleanupDone")
	require.NoError(t, receiveSiriusGateResult(t, second),
		"the poisoned owner remains retryable for resource cleanup")
	require.ErrorContains(t, receiveSiriusGateResult(t, admission), "admission is sealed")
	require.Zero(t, storageStarts.Load(), "a cleanup retry must never hand off poisoned admission")
	require.Equal(t, int32(2), cleanupAttempts.Load())
}

func TestSiriusEmbeddedMOAndTAEShareAdmissionGate(t *testing.T) {
	moRuntime := &SiriusRuntime{Source: SiriusRuntimeEmbeddedMO}
	require.NoError(t, moRuntime.InitEmbeddedAdmission(1))
	taeRuntime := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedTAE, embeddedAdmission: moRuntime.embeddedAdmission,
	}
	taeRuntime.Leases = substrait.NewPersistentLeaseManager(
		1, &siriusRuntimeTestProtector{}, siriusDurableJournalStub{})
	require.NoError(t, taeRuntime.Leases.Replay(t.Context()))
	taeRuntime.LeaseCapability = siriusRuntimeTestCapabilityFor(t, taeRuntime.Leases)
	moPermit, err := moRuntime.acquireEmbeddedAdmission(context.Background())
	require.NoError(t, err)
	type result struct {
		permit *siriusEmbeddedAdmissionPermit
		err    error
	}
	taeResult := make(chan result, 1)
	go func() {
		permit, acquireErr := taeRuntime.acquireEmbeddedAdmission(context.Background())
		taeResult <- result{permit: permit, err: acquireErr}
	}()
	waitForSiriusGateWaiters(t, moRuntime.embeddedAdmission, 1)
	moPermit.release()
	tae := receiveSiriusGateResult(t, taeResult)
	require.NoError(t, tae.err)
	tae.permit.release()
}

func TestSiriusEmbeddedAdmissionConfiguration(t *testing.T) {
	require.Error(t, (*SiriusRuntime)(nil).InitEmbeddedAdmission(1))
	require.Error(t, (&SiriusRuntime{Source: SiriusRuntimeFlight}).InitEmbeddedAdmission(1))
	siriusRuntime := &SiriusRuntime{Source: SiriusRuntimeEmbeddedMO}
	require.NoError(t, siriusRuntime.InitEmbeddedAdmission(0), "zero selects the default")
	require.Equal(t, int(defaultSiriusEmbeddedMaxWaiting), siriusRuntime.embeddedAdmission.maxWaiting)
	require.ErrorContains(t, siriusRuntime.InitEmbeddedAdmission(1), "already initialized")
	require.Error(t, (&SiriusRuntime{Source: SiriusRuntimeEmbeddedMO}).InitEmbeddedAdmission(17))
}

func TestSiriusStorageRevocationSealsQueuedAdmissionButPreservesActiveOwner(t *testing.T) {
	manager := substrait.NewPersistentLeaseManager(
		1, &siriusRuntimeTestProtector{}, siriusDurableJournalStub{})
	require.NoError(t, manager.Replay(t.Context()))
	broker, capability := siriusRuntimeTestBrokerCapabilityFor(t, manager)
	runtime := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, Backend: new(siriusReconcileBackend),
		CleanupTimeout: time.Second, LeaseCapability: capability,
	}
	require.NoError(t, runtime.InitEmbeddedAdmission(1))
	active, err := runtime.acquireEmbeddedAdmission(t.Context())
	require.NoError(t, err)
	waiter := make(chan error, 1)
	go func() {
		permit, acquireErr := runtime.acquireEmbeddedAdmission(context.Background())
		if permit != nil {
			permit.release()
		}
		waiter <- acquireErr
	}()
	waitForSiriusGateWaiters(t, runtime.embeddedAdmission, 1)

	refuse, err := broker.RevokeStorage(capability.StorageIdentity())
	require.NoError(t, err)
	require.True(t, refuse)
	require.ErrorContains(t, runtime.Validate(), "capability is revoked")
	require.ErrorContains(t, receiveSiriusGateResult(t, waiter), "admission is sealed")
	runtime.embeddedAdmission.mu.Lock()
	require.True(t, runtime.embeddedAdmission.active,
		"revocation must not steal the active query's cleanup ownership")
	runtime.embeddedAdmission.mu.Unlock()
	active.release()
}
