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
	"sync"
	"time"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/common/mpool"
	moruntime "github.com/matrixorigin/matrixone/pkg/common/runtime"
	"github.com/matrixorigin/matrixone/pkg/defines"
	planpb "github.com/matrixorigin/matrixone/pkg/pb/plan"
	"github.com/matrixorigin/matrixone/pkg/sql/parsers/tree"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
)

// SiriusRuntimeKey is service-scoped: separate CNs must never share ticket or
// resolver ownership through the process default runtime.
const SiriusRuntimeKey = "sql-compile-sirius-runtime"

type siriusOffloadContextKey struct{}

// SiriusRuntimeSource selects the only read owner a CN runtime may publish.
// The zero value preserves the existing Flight deployment contract.
type SiriusRuntimeSource uint8

const (
	SiriusRuntimeFlight SiriusRuntimeSource = iota
	SiriusRuntimeEmbeddedMO
	SiriusRuntimeEmbeddedTAE
)

func (s SiriusRuntimeSource) embedded() bool {
	return s == SiriusRuntimeEmbeddedMO || s == SiriusRuntimeEmbeddedTAE
}

// WithSiriusOffload marks an explicitly hinted statement. Absence of this
// marker leaves every native compile and execution path unchanged.
func WithSiriusOffload(ctx context.Context) context.Context {
	return context.WithValue(ctx, siriusOffloadContextKey{}, true)
}

func siriusOffloadRequested(ctx context.Context) bool {
	requested, _ := ctx.Value(siriusOffloadContextKey{}).(bool)
	return requested
}

func siriusStatementEligible(stmt tree.Statement) bool {
	selectStmt, ok := stmt.(*tree.Select)
	return ok && !selectStmt.IsPerform && selectStmt.Ep == nil && !statementHasSQLCalcFoundRows(stmt)
}

func siriusPlanEligible(queryPlan *planpb.Plan) bool {
	return queryPlan == nil || len(queryPlan.GetQuery().GetUnresolvedIndexHints()) == 0
}

// SiriusRuntime is initialized and closed by one CN service. Production lease
// managers are supplied by the storage/GC integration because constructing an
// unprotected CN-local substitute would violate snapshot safety. The only
// exception is the explicit local-CN benchmark mode, where TN GC is disabled,
// and each CN owns one process-local manager and one sidecar pairing.
type SiriusRuntime struct {
	// Source is Flight by default. Embedded MO has no lease dependency;
	// embedded TAE requires the same durable snapshot protection as Flight.
	Source                   SiriusRuntimeSource
	Backend                  SiriusBackend
	Leases                   *substrait.LeaseManager
	Resolver                 *substrait.ResolverServer
	AuthorizedClientSPKIHash []byte
	DataDir                  string
	LeaseTTL                 time.Duration
	CleanupTimeout           time.Duration
	embeddedAdmission        *siriusEmbeddedAdmissionGate
	// BenchmarkNoGC is set only by the CN launcher after it verifies that the
	// paired TN has disabled GC. It permits the explicitly non-durable,
	// process-local lease manager used by the local-CN benchmark profile.
	BenchmarkNoGC bool
}

// InitEmbeddedAdmission installs the runtime-scoped admission gate before the
// runtime is published to a CN. A zero value selects the design default of 16
// queued requests. The runtime is immutable after publication, so repeated
// initialization is rejected rather than replacing a live generation.
func (r *SiriusRuntime) InitEmbeddedAdmission(maxWaiting uint32) error {
	if r == nil || !r.Source.embedded() {
		return moerr.NewBadConfigNoCtx("Sirius embedded admission requires an embedded runtime")
	}
	if r.embeddedAdmission != nil {
		return moerr.NewInvalidStateNoCtx("substrait: embedded Sirius admission is already initialized")
	}
	gate, err := newSiriusEmbeddedAdmissionGate(maxWaiting)
	if err != nil {
		return err
	}
	r.embeddedAdmission = gate
	return nil
}

func (r *SiriusRuntime) Validate() error {
	if r == nil || r.Backend == nil || r.CleanupTimeout <= 0 {
		return moerr.NewInternalErrorNoCtx("substrait: incomplete CN Sirius runtime")
	}
	if r.Source.embedded() {
		if r.embeddedAdmission == nil || !r.embeddedAdmission.accepting() {
			return moerr.NewInvalidStateNoCtx("substrait: embedded Sirius admission is sealed or uninitialized")
		}
		if r.BenchmarkNoGC {
			return moerr.NewInternalErrorNoCtx("substrait: embedded Sirius cannot use benchmark lease mode")
		}
		if r.Source == SiriusRuntimeEmbeddedTAE &&
			(r.Leases == nil || !r.Leases.DurableReady() || r.DataDir == "" ||
				r.LeaseTTL <= r.CleanupTimeout || r.LeaseTTL > substrait.MaxLeaseTTL) {
			return moerr.NewInternalErrorNoCtx("substrait: incomplete embedded TAE Sirius runtime")
		}
		if health, ok := r.Backend.(interface{ Accepting() bool }); ok && !health.Accepting() {
			return moerr.NewInvalidStateNoCtx("substrait: embedded Sirius admission is sealed")
		}
		return nil
	}
	if r.Source != SiriusRuntimeFlight || r.Leases == nil ||
		r.Resolver == nil || !nonzeroSiriusSPKI(r.AuthorizedClientSPKIHash) || r.DataDir == "" ||
		r.LeaseTTL <= r.CleanupTimeout || r.LeaseTTL > substrait.MaxLeaseTTL {
		return moerr.NewInternalErrorNoCtx("substrait: incomplete CN Sirius runtime")
	}
	if r.BenchmarkNoGC {
		if !r.Leases.BenchmarkReady() {
			return moerr.NewInternalErrorNoCtx("substrait: incomplete benchmark CN Sirius runtime")
		}
	} else if !r.Leases.DurableReady() {
		return moerr.NewInternalErrorNoCtx("substrait: incomplete CN Sirius runtime")
	}
	return nil
}

func nonzeroSiriusSPKI(hash []byte) bool {
	if len(hash) != 32 {
		return false
	}
	for _, value := range hash {
		if value != 0 {
			return true
		}
	}
	return false
}

// Close obeys the ownership order: stop/cancel backend work first, then close
// the resolver that serves the leases retained by that work.
func (r *SiriusRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var result error
	if r.Source.embedded() && r.embeddedAdmission != nil {
		// Wake queued callers before a potentially blocking native close. The
		// active permit remains owned by its execution until that owner quiesces.
		r.embeddedAdmission.seal()
	}
	if r.Backend != nil {
		result = errors.Join(result, r.Backend.Close(ctx))
	}
	if r.Resolver != nil {
		result = errors.Join(result, r.Resolver.Close(ctx))
	}
	return result
}

// ReconcileReplay transfers durable leases left by a prior CN generation to
// the backend's retry owner. Cancellation by statement identity is idempotent, and
// lease release starts only after the sidecar acknowledges quiescence.
func (r *SiriusRuntime) ReconcileReplay(ctx context.Context) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Source == SiriusRuntimeEmbeddedMO {
		return nil
	}
	consumer := substrait.ReadConsumerFlight
	if r.Source == SiriusRuntimeEmbeddedTAE {
		consumer = substrait.ReadConsumerEmbeddedTAE
	}
	pending, err := r.Leases.ReconcileRestart(ctx, consumer)
	if err != nil {
		return err
	}
	if r.Source == SiriusRuntimeEmbeddedTAE {
		return nil
	}
	var result error
	for _, execution := range pending {
		readRefs := cloneReadRefs(execution.ReadRefs)
		err := r.Backend.Reconcile(execution.AccountID, execution.QueryID, func(ctx context.Context) error {
			return releaseReadRefs(ctx, r.Leases, readRefs)
		})
		result = errors.Join(result, err)
	}
	return result
}

func lookupSiriusRuntime(service string) (*SiriusRuntime, bool) {
	runtime := moruntime.ServiceRuntime(service)
	if runtime == nil {
		return nil, false
	}
	value, ok := runtime.GetGlobalVariables(SiriusRuntimeKey)
	if !ok {
		return nil, false
	}
	result, ok := value.(*SiriusRuntime)
	return result, ok && result != nil && result.Validate() == nil
}

type siriusReadOwner struct {
	execution      SiriusExecution
	runtime        *SiriusRuntime
	source         SiriusRuntimeSource
	permit         *siriusEmbeddedAdmissionPermit
	cleanupMu      sync.Mutex
	cleanupRunning bool
	cleanupDone    chan struct{}
	cleaned        bool
}

func newSiriusReadOwner(execution SiriusExecution, runtime *SiriusRuntime) *siriusReadOwner {
	return &siriusReadOwner{execution: execution, runtime: runtime, source: SiriusRuntimeFlight}
}

func newSiriusEmbeddedReadOwner(
	execution SiriusExecution,
	runtime *SiriusRuntime,
	permit *siriusEmbeddedAdmissionPermit,
) *siriusReadOwner {
	return &siriusReadOwner{
		execution: execution,
		runtime:   runtime,
		source:    runtime.Source,
		permit:    permit,
	}
}

func (o *siriusReadOwner) finish(ctx context.Context, succeeded bool) error {
	if o == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !o.source.embedded() {
		// Flight keeps its established cleanup behavior. Its execution object
		// already owns retry/concurrent-close state; the outer embedded permit
		// state machine is neither needed nor applied to it.
		cleanupCtx, cancel := context.WithTimeoutCause(context.WithoutCancel(ctx), o.runtime.CleanupTimeout,
			moerr.NewInternalErrorNoCtx("substrait: timed out cleaning up Sirius execution"))
		defer cancel()
		if succeeded {
			return o.execution.CleanupAfterRun(cleanupCtx, nil)
		}
		return o.execution.Cleanup(cleanupCtx)
	}
	for {
		o.cleanupMu.Lock()
		if o.cleaned {
			o.cleanupMu.Unlock()
			return nil
		}
		if o.cleanupRunning {
			done := o.cleanupDone
			o.cleanupMu.Unlock()
			select {
			case <-done:
				// A failed owner remains retryable; claim the next attempt.
				continue
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		o.cleanupRunning = true
		o.cleanupDone = make(chan struct{})
		done := o.cleanupDone
		o.cleanupMu.Unlock()

		cleanupErr := o.cleanupAttempt(ctx, succeeded)
		if cleanupErr != nil {
			// Poison admission before publishing attempt completion. Otherwise a
			// concurrent finish caller can observe cleanupDone, retry successfully,
			// and hand the permit to queued storage work before this caller seals.
			o.runtime.sealEmbeddedAdmission()
		}
		o.cleanupMu.Lock()
		if cleanupErr == nil {
			o.cleaned = true
		}
		o.cleanupRunning = false
		close(done)
		o.cleanupMu.Unlock()

		// Cleanup must complete (or fail and seal admission) before another
		// embedded query can own the selected GPU. The permit is once-release,
		// while a failed execution owner remains available for cleanup retry.
		o.permit.release()
		return cleanupErr
	}
}

func (o *siriusReadOwner) cleanupAttempt(ctx context.Context, succeeded bool) (result error) {
	cleanupCtx, cancel := context.WithTimeoutCause(context.WithoutCancel(ctx), o.runtime.CleanupTimeout,
		moerr.NewInternalErrorNoCtx("substrait: timed out cleaning up Sirius execution"))
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			result = moerr.NewInternalErrorNoCtxf(
				"substrait: panic cleaning up Sirius execution: %v", recovered)
		}
	}()
	if succeeded {
		return o.execution.CleanupAfterRun(cleanupCtx, nil)
	}
	return o.execution.Cleanup(cleanupCtx)
}

func (c *Compile) tryCompileSiriusRead(ctx context.Context, queryPlan *planpb.Plan) (bool, error) {
	if c == nil || c.proc == nil || !siriusOffloadRequested(ctx) || c.isPrepare || c.isInternal {
		return false, nil
	}
	runtime, ok := lookupSiriusRuntime(c.proc.GetService())
	if runtime != nil && runtime.Source.embedded() {
		// An explicitly selected embedded runtime must not turn failed
		// admission into an invisible CPU fallback.
		if err := runtime.Validate(); err != nil {
			return false, err
		}
		if !siriusStatementEligible(c.stmt) {
			return false, moerr.NewNotSupported(ctx, "embedded Sirius requires an ordinary SELECT statement")
		}
		if !siriusPlanEligible(queryPlan) {
			return false, moerr.NewNotSupported(ctx, "embedded Sirius cannot execute an unresolved index hint")
		}
		return c.tryCompileEmbeddedSiriusRead(ctx, queryPlan, runtime)
	}
	if !ok {
		return false, nil
	}
	if !siriusStatementEligible(c.stmt) {
		return false, nil
	}
	if !siriusPlanEligible(queryPlan) {
		// Normal compilation owns the metadata-lock/retry boundary for a stale
		// index hint. An offloaded plan cannot bypass that validation.
		return false, nil
	}
	accountID, err := defines.GetAccountId(ctx)
	if err != nil {
		return false, nil
	}
	statementID := c.proc.GetStmtProfile().GetStmtId()
	queryID := append([]byte(nil), statementID[:]...)
	readPlan, err := c.CompileSiriusRead(
		ctx, queryPlan, uint64(accountID), queryID, runtime.AuthorizedClientSPKIHash,
		runtime.DataDir, runtime.LeaseTTL, runtime.Leases,
	)
	if err != nil {
		if readPlan != nil {
			return false, errors.Join(err, runtime.recoverAdmittedRead(ctx, uint64(accountID), queryID, readPlan))
		}
		if substrait.IsNotEligible(err) {
			return false, nil
		}
		return false, err
	}
	execution, prepareErr := runtime.Backend.Prepare(ctx, SiriusPrepareRequest{
		AccountID: uint64(accountID), QueryID: queryID, Plan: readPlan.Plan,
		OutputTypes: readPlan.OutputTypes, Headings: readPlan.Headings,
		Deadline: readPlan.LeaseExpiresAt.Add(-runtime.CleanupTimeout),
		Release: func(releaseCtx context.Context) error {
			return readPlan.Release(releaseCtx, runtime.Leases)
		},
	})
	if prepareErr != nil {
		if runtime.Backend.CanFallbackBeforeVisibility(prepareErr) {
			return false, nil
		}
		return false, prepareErr
	}
	c.siriusRead = newSiriusReadOwner(execution, runtime)
	return true, nil
}

// recoverAdmittedRead handles an operational failure after admission but
// before any backend request exists. It first attempts bounded synchronous
// release. If any release fails, durable ownership transfers to the backend's
// identity-based reconciliation worker, which retries idempotent release.
func (r *SiriusRuntime) recoverAdmittedRead(ctx context.Context, accountID uint64, queryID []byte, plan *SiriusReadPlan) error {
	if r == nil || r.Backend == nil || plan == nil {
		return moerr.NewInternalErrorNoCtx("substrait: cannot recover admitted read without a runtime owner")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cleanupCtx, cancel := context.WithTimeoutCause(context.WithoutCancel(ctx), r.CleanupTimeout,
		moerr.NewInternalErrorNoCtx("substrait: timed out releasing admitted Sirius reads"))
	releaseErr := plan.Release(cleanupCtx, r.Leases)
	cancel()
	if releaseErr == nil {
		return nil
	}
	readRefs := cloneReadRefs(plan.ReadRefs)
	reconcileErr := r.Backend.Reconcile(accountID, append([]byte(nil), queryID...), func(releaseCtx context.Context) error {
		return releaseReadRefs(releaseCtx, r.Leases, readRefs)
	})
	return errors.Join(releaseErr, reconcileErr)
}

// abortEmbeddedAdmittedRead handles the narrow invariant-failure window after
// embedded TAE admission but before Backend.Prepare owns Release. A failed
// local release seals native admission; durable protection remains for restart
// reconciliation rather than being left behind an accepting runtime.
func (r *SiriusRuntime) abortEmbeddedAdmittedRead(
	ctx context.Context,
	plan *SiriusReadPlan,
	cause error,
) error {
	cleanupCtx, cancel := context.WithTimeoutCause(context.WithoutCancel(ctx), r.CleanupTimeout,
		moerr.NewInternalErrorNoCtx("substrait: timed out releasing embedded TAE admission"))
	releaseErr := func() (result error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				result = moerr.NewInternalErrorNoCtxf(
					"substrait: panic releasing embedded TAE admission: %v", recovered)
			}
		}()
		return plan.Release(cleanupCtx, r.Leases)
	}()
	cancel()
	if releaseErr == nil {
		return cause
	}
	return errors.Join(cause, releaseErr, r.sealEmbeddedRuntime(ctx, nil))
}

func (r *SiriusRuntime) sealEmbeddedRuntime(ctx context.Context, cause error) error {
	if r == nil {
		return errors.Join(cause, moerr.NewInternalErrorNoCtx("substrait: cannot seal a nil embedded runtime"))
	}
	cleanupCtx, cancel := context.WithTimeoutCause(context.WithoutCancel(ctx), r.CleanupTimeout,
		moerr.NewInternalErrorNoCtx("substrait: timed out sealing embedded Sirius runtime"))
	defer cancel()
	return errors.Join(cause, r.Close(cleanupCtx))
}

func (r *SiriusRuntime) sealEmbeddedAdmission() {
	if r != nil && r.embeddedAdmission != nil {
		r.embeddedAdmission.seal()
	}
}

func (r *SiriusRuntime) prepareEmbeddedExecution(
	ctx context.Context,
	request SiriusPrepareRequest,
) (SiriusExecution, error) {
	execution, err := r.Backend.Prepare(ctx, request)
	if err != nil {
		if health, ok := r.Backend.(interface{ Accepting() bool }); ok && !health.Accepting() {
			// A native cleanup failure can seal the backend while this Go permit
			// is still active. Seal the outer queue before its deferred handoff.
			r.sealEmbeddedAdmission()
		}
		return nil, err
	}
	if execution == nil {
		r.sealEmbeddedAdmission()
		return nil, moerr.NewInternalErrorNoCtx(
			"substrait: embedded preparation returned no execution")
	}
	return execution, nil
}

func cloneReadRefs(readRefs [][]byte) [][]byte {
	result := make([][]byte, len(readRefs))
	for i := range readRefs {
		result[i] = append([]byte(nil), readRefs[i]...)
	}
	return result
}

func releaseReadRefs(ctx context.Context, leases *substrait.LeaseManager, readRefs [][]byte) error {
	var result error
	for _, readRef := range readRefs {
		result = errors.Join(result, leases.Release(ctx, readRef))
	}
	return result
}

func (c *Compile) runSiriusRead(
	ctx context.Context,
	allocationExporter func(mpool.AllocationAccountTerminalSnapshot),
) (err error) {
	owner := c.siriusRead
	if owner == nil {
		return moerr.NewInternalError(ctx, "substrait: missing Sirius execution owner")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = owner.finish(ctx, false)
			panic(recovered)
		}
	}()
	if owner.source == SiriusRuntimeEmbeddedMO {
		return c.runSiriusEmbeddedRead(ctx, owner, allocationExporter)
	}
	runErr := owner.execution.Run(ctx, c.proc.Mp(), c.counterSet, c.fill)
	return errors.Join(runErr, owner.finish(ctx, runErr == nil))
}

func (c *Compile) runSiriusEmbeddedRead(
	ctx context.Context,
	owner *siriusReadOwner,
	allocationExporter func(mpool.AllocationAccountTerminalSnapshot),
) (err error) {
	if c.MessageBoard == nil {
		return errors.Join(
			moerr.NewInternalError(ctx, "substrait: embedded Sirius execution has no message board"),
			owner.finish(ctx, false),
		)
	}
	c.remoteFragmentCounts = collectRemoteFragmentCounts(c.scopes, c.addr)
	if len(c.remoteFragmentCounts) != 0 {
		return errors.Join(
			moerr.NewInternalError(ctx, "substrait: embedded Sirius execution is not local-CN"),
			owner.finish(ctx, false),
		)
	}
	if err = c.ensureAllocationAccountLifecycle(allocationExporter); err != nil {
		return errors.Join(err, owner.finish(ctx, false))
	}
	attempt, err := c.beginAllocationAccountAttempt()
	if err != nil {
		return errors.Join(err, owner.finish(ctx, false))
	}
	defer func() {
		if attempt == nil {
			return
		}
		_, finishErr := attempt.finish()
		if c.allocationAttempt == attempt {
			c.allocationAttempt = nil
		}
		err = errors.Join(err, finishErr)
	}()
	runErr := owner.execution.Run(ctx, c.proc.Mp(), c.counterSet, c.fill)
	return errors.Join(runErr, owner.finish(ctx, runErr == nil))
}
