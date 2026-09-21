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
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	moruntime "github.com/matrixorigin/matrixone/pkg/common/runtime"
	"github.com/matrixorigin/matrixone/pkg/container/types"
	"github.com/matrixorigin/matrixone/pkg/pb/metadata"
	planpb "github.com/matrixorigin/matrixone/pkg/pb/plan"
	"github.com/matrixorigin/matrixone/pkg/sql/compile/sidecarflight"
	"github.com/matrixorigin/matrixone/pkg/sql/parsers/tree"
	plan2 "github.com/matrixorigin/matrixone/pkg/sql/plan"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/testutil"
	"github.com/stretchr/testify/require"
	spb "github.com/substrait-io/substrait-protobuf/go/substraitpb"
	"google.golang.org/protobuf/proto"
)

type siriusRuntimeTestProtector struct{ failUnregister bool }

type siriusDurableJournalStub struct{}

func (siriusDurableJournalStub) StoreIfCapacity(_ context.Context, leases []*substrait.Lease, _ int) (int, error) {
	return len(leases), nil
}
func (siriusDurableJournalStub) Active(context.Context, *substrait.Lease) (bool, error) {
	return false, nil
}
func (siriusDurableJournalStub) MarkReleased(context.Context, []byte) error { return nil }
func (siriusDurableJournalStub) Delete(context.Context, []byte) error       { return nil }
func (siriusDurableJournalStub) Load(context.Context, func(*substrait.Lease) error) error {
	return nil
}

func (*siriusRuntimeTestProtector) Begin(context.Context) (
	func(context.Context, []byte, []string, time.Time) error,
	func(context.Context, []byte) error,
	func(),
	error,
) {
	return func(context.Context, []byte, []string, time.Time) error { return nil },
		func(context.Context, []byte) error { return nil }, func() {}, nil
}

func (p *siriusRuntimeTestProtector) Unregister(context.Context, []byte) error {
	if p.failUnregister {
		return errors.New("test unregister failure")
	}
	return nil
}

func siriusRuntimeTestCapabilityFor(
	t *testing.T,
	manager *substrait.LeaseManager,
) *substrait.LeaseManagerCapability {
	_, capability := siriusRuntimeTestBrokerCapabilityFor(t, manager)
	return capability
}

func siriusRuntimeTestBrokerCapabilityFor(
	t *testing.T,
	manager *substrait.LeaseManager,
) (*substrait.LeaseManagerBroker, *substrait.LeaseManagerCapability) {
	t.Helper()
	broker := substrait.NewLeaseManagerBroker()
	publication, err := broker.Prepare("test-tae-shard/1/replica/1", manager)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())
	capability, err := broker.AttestTopology("test-tae-shard/1/replica/1", time.Minute)
	require.NoError(t, err)
	return broker, capability
}

type siriusRuntimeTestProvider struct{ schema []byte }

func (p siriusRuntimeTestProvider) PrepareSnapshotRead(context.Context, substrait.Read, []byte) (substrait.SnapshotFacts, error) {
	return substrait.SnapshotFacts{Manifest: []byte("manifest"), CanonicalSchema: p.schema}, nil
}

func (p siriusRuntimeTestProvider) PrepareSnapshotReadBounded(
	ctx context.Context,
	read substrait.Read,
	snapshot []byte,
	_ int,
) (substrait.SnapshotFacts, error) {
	return p.PrepareSnapshotRead(ctx, read, snapshot)
}

func TestSiriusRuntimeValidationAndLookup(t *testing.T) {
	require.Error(t, (*SiriusRuntime)(nil).Validate())
	require.NoError(t, (*SiriusRuntime)(nil).Close(context.Background()))

	nondurable := substrait.NewLeaseManager(1, &siriusRuntimeTestProtector{})
	invalid := &SiriusRuntime{
		Backend: NewSiriusFlightBackend(&sidecarflight.Runtime{}), Leases: nondurable, Resolver: &substrait.ResolverServer{},
		AuthorizedClientSPKIHash: bytes.Repeat([]byte{1}, 32), DataDir: t.TempDir(), LeaseTTL: time.Minute, CleanupTimeout: time.Second,
	}
	require.Error(t, invalid.Validate())
	benchmark := *invalid
	benchmark.BenchmarkNoGC = true
	benchmark.Leases = substrait.NewBenchmarkLeaseManager(1, &siriusRuntimeTestProtector{})
	require.NoError(t, benchmark.Validate())
	require.False(t, nondurable.BenchmarkReady())
	wrongNormalMode := benchmark
	wrongNormalMode.BenchmarkNoGC = false
	require.ErrorContains(t, wrongNormalMode.Validate(), "incomplete CN Sirius runtime")
	leases := substrait.NewPersistentLeaseManager(1, &siriusRuntimeTestProtector{}, siriusDurableJournalStub{})
	require.NoError(t, leases.Replay(context.Background()))
	valid := &SiriusRuntime{
		Backend:  NewSiriusFlightBackend(&sidecarflight.Runtime{}),
		Leases:   leases,
		Resolver: &substrait.ResolverServer{}, AuthorizedClientSPKIHash: bytes.Repeat([]byte{1}, 32),
		DataDir: t.TempDir(), LeaseTTL: time.Minute, CleanupTimeout: time.Second,
	}
	require.NoError(t, valid.Validate())
	zeroSPKI := *valid
	zeroSPKI.AuthorizedClientSPKIHash = make([]byte, 32)
	require.ErrorContains(t, zeroSPKI.Validate(), "incomplete CN Sirius runtime")
	embeddedMO := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, Backend: &siriusAdmissionBackend{accepting: true},
		CleanupTimeout: time.Second,
	}
	require.NoError(t, embeddedMO.InitEmbeddedAdmission(16))
	require.NoError(t, embeddedMO.Validate())
	embeddedTAE := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedTAE, Backend: &siriusAdmissionBackend{accepting: true},
		Leases: leases, LeaseCapability: siriusRuntimeTestCapabilityFor(t, leases),
		DataDir: t.TempDir(), LeaseTTL: time.Minute, CleanupTimeout: time.Second,
	}
	require.NoError(t, embeddedTAE.InitEmbeddedAdmission(16))
	require.NoError(t, embeddedTAE.Validate())
	embeddedTAE.Leases = nondurable
	require.ErrorContains(t, embeddedTAE.Validate(), "incomplete embedded TAE Sirius runtime")
	wrongBenchmarkMode := *valid
	wrongBenchmarkMode.BenchmarkNoGC = true
	require.ErrorContains(t, wrongBenchmarkMode.Validate(), "incomplete benchmark CN Sirius runtime")

	service := "sirius-runtime-lookup-test"
	rt := moruntime.NewRuntime(metadata.ServiceType_CN, service, nil)
	moruntime.SetupServiceBasedRuntime(service, rt)
	_, ok := lookupSiriusRuntime("sirius-runtime-missing")
	require.False(t, ok)
	rt.SetGlobalVariables(SiriusRuntimeKey, "wrong type")
	_, ok = lookupSiriusRuntime(service)
	require.False(t, ok)
	rt.SetGlobalVariables(SiriusRuntimeKey, &SiriusRuntime{})
	_, ok = lookupSiriusRuntime(service)
	require.False(t, ok)
	rt.SetGlobalVariables(SiriusRuntimeKey, valid)
	actual, ok := lookupSiriusRuntime(service)
	require.True(t, ok)
	require.Same(t, valid, actual)
	require.True(t, rt.CompareAndDeleteGlobalVariables(SiriusRuntimeKey, valid))
}

func TestSiriusRuntimeRevokedStorageCapabilityRejectsNewLocalQueries(t *testing.T) {
	manager := substrait.NewPersistentLeaseManager(
		1, &siriusRuntimeTestProtector{}, siriusDurableJournalStub{})
	require.NoError(t, manager.Replay(t.Context()))
	broker, capability := siriusRuntimeTestBrokerCapabilityFor(t, manager)
	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	rt := moruntime.ServiceRuntime(proc.GetService())
	previous, existed := rt.GetGlobalVariables(SiriusRuntimeKey)
	flight := &SiriusRuntime{
		Backend: new(siriusReconcileBackend), Leases: manager,
		Resolver: &substrait.ResolverServer{}, LeaseCapability: capability,
		AuthorizedClientSPKIHash: bytes.Repeat([]byte{1}, 32), DataDir: t.TempDir(),
		LeaseTTL: time.Minute, CleanupTimeout: time.Second,
	}
	require.NoError(t, flight.Validate())
	rt.SetGlobalVariables(SiriusRuntimeKey, flight)
	t.Cleanup(func() {
		if existed {
			rt.SetGlobalVariables(SiriusRuntimeKey, previous)
		} else {
			rt.CompareAndDeleteGlobalVariables(SiriusRuntimeKey, flight)
		}
	})

	refuse, err := broker.RevokeStorage(capability.StorageIdentity())
	require.NoError(t, err)
	require.True(t, refuse)
	actual, ok := lookupSiriusRuntime(proc.GetService())
	require.Same(t, flight, actual)
	require.False(t, ok)
	c := allocateNewCompile(proc)
	c.stmt = &tree.Select{}
	offloaded, err := c.tryCompileSiriusRead(WithSiriusOffload(context.Background()), nil)
	require.False(t, offloaded)
	require.ErrorContains(t, err, "capability is revoked")

	moBroker, moCapability := siriusRuntimeTestBrokerCapabilityFor(t, manager)
	mo := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, Backend: new(siriusReconcileBackend),
		CleanupTimeout: time.Second, LeaseCapability: moCapability,
	}
	require.NoError(t, mo.InitEmbeddedAdmission(1))
	require.NoError(t, mo.Validate())
	refuse, err = moBroker.RevokeStorage(moCapability.StorageIdentity())
	require.NoError(t, err)
	require.True(t, refuse)
	require.ErrorContains(t, mo.Validate(), "capability is revoked")
	require.False(t, mo.embeddedAdmission.accepting())
}

type siriusReconcileBackend struct {
	reconciled int
}

func (*siriusReconcileBackend) Prepare(context.Context, SiriusPrepareRequest) (SiriusExecution, error) {
	return nil, errors.New("not used")
}
func (b *siriusReconcileBackend) Reconcile(_ uint64, _ []byte, release func(context.Context) error) error {
	b.reconciled++
	return release(context.Background())
}
func (*siriusReconcileBackend) Close(context.Context) error            { return nil }
func (*siriusReconcileBackend) CanFallbackBeforeVisibility(error) bool { return false }

func TestSiriusReplayReconcilesOnlyFlightAndEmbeddedTAERejectsIt(t *testing.T) {
	query := &planpb.Query{
		StmtType: planpb.Query_SELECT, Steps: []int32{0}, Headings: []string{"a"},
		Nodes: []*planpb.Node{{
			NodeId: 0, NodeType: planpb.Node_TABLE_SCAN,
			ObjRef: &planpb.ObjectRef{Obj: 42, ObjName: "t"},
			TableDef: &planpb.TableDef{DbId: 7, TblId: 42, Version: 3, Name: "t", TableType: "r", Cols: []*planpb.ColDef{{
				Name: "a", ColId: 11, Seqnum: 5, Typ: planpb.Type{Id: int32(types.T_int64)},
			}}},
		}},
	}
	candidate, err := substrait.Export(query)
	require.NoError(t, err)
	provider := siriusRuntimeTestProvider{schema: candidate.Reads()[0].Schema}
	newManager := func() *substrait.LeaseManager {
		manager := substrait.NewPersistentLeaseManager(2, &siriusRuntimeTestProtector{}, siriusDurableJournalStub{})
		require.NoError(t, manager.Replay(context.Background()))
		return manager
	}
	admit := func(manager *substrait.LeaseManager, consumer substrait.ReadConsumer, queryID byte) {
		request := substrait.AdmissionRequest{
			Candidate: candidate, Provider: provider, Leases: manager, AccountID: 1,
			QueryID: bytes.Repeat([]byte{queryID}, 16), SnapshotTS: make([]byte, 12),
			Consumer: consumer, TTL: time.Minute, ReadOnly: true,
		}
		if consumer == substrait.ReadConsumerFlight {
			request.AuthorizedClientSPKIHash = bytes.Repeat([]byte{1}, 32)
		}
		_, admitErr := substrait.AdmitReads(context.Background(), request)
		require.NoError(t, admitErr)
	}

	flightManager := newManager()
	admit(flightManager, substrait.ReadConsumerFlight, 'f')
	admit(flightManager, substrait.ReadConsumerEmbeddedTAE, 'e')
	backend := new(siriusReconcileBackend)
	flight := &SiriusRuntime{
		Backend: backend, Leases: flightManager, Resolver: &substrait.ResolverServer{},
		AuthorizedClientSPKIHash: bytes.Repeat([]byte{1}, 32), DataDir: t.TempDir(),
		LeaseTTL: time.Minute, CleanupTimeout: time.Second,
	}
	require.NoError(t, flight.ReconcileReplay(context.Background()))
	require.Equal(t, 1, backend.reconciled, "only the Flight group is handed to the backend")
	require.Empty(t, flightManager.PendingExecutions())

	embeddedManager := newManager()
	admit(embeddedManager, substrait.ReadConsumerFlight, 'x')
	embedded := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedTAE, Backend: new(siriusReconcileBackend),
		Leases: embeddedManager, DataDir: t.TempDir(), LeaseTTL: time.Minute,
		CleanupTimeout: time.Second, LeaseCapability: siriusRuntimeTestCapabilityFor(t, embeddedManager),
	}
	require.NoError(t, embedded.InitEmbeddedAdmission(16))
	require.ErrorContains(t, embedded.ReconcileReplay(context.Background()), "unreconciled Flight reads")

	mo := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, Backend: new(siriusReconcileBackend), CleanupTimeout: time.Second,
	}
	require.NoError(t, mo.InitEmbeddedAdmission(16))
	require.NoError(t, mo.ReconcileReplay(context.Background()))
}

func TestEmbeddedTAEAbortSealsRuntimeWhenLocalReleaseNeedsRetry(t *testing.T) {
	query := &planpb.Query{
		StmtType: planpb.Query_SELECT, Steps: []int32{0}, Headings: []string{"a"},
		Nodes: []*planpb.Node{{
			NodeId: 0, NodeType: planpb.Node_TABLE_SCAN,
			ObjRef: &planpb.ObjectRef{Obj: 42, ObjName: "t"},
			TableDef: &planpb.TableDef{DbId: 7, TblId: 42, Version: 3, Name: "t", TableType: "r", Cols: []*planpb.ColDef{{
				Name: "a", ColId: 11, Seqnum: 5, Typ: planpb.Type{Id: int32(types.T_int64)},
			}}},
		}},
	}
	candidate, err := substrait.Export(query)
	require.NoError(t, err)
	protector := &siriusRuntimeTestProtector{}
	leases := substrait.NewPersistentLeaseManager(1, protector, siriusDurableJournalStub{})
	require.NoError(t, leases.Replay(context.Background()))
	admitted, err := substrait.AdmitReads(context.Background(), substrait.AdmissionRequest{
		Candidate: candidate, Provider: siriusRuntimeTestProvider{schema: candidate.Reads()[0].Schema},
		Leases: leases, AccountID: 1, QueryID: bytes.Repeat([]byte{'e'}, 16),
		SnapshotTS: make([]byte, 12), Consumer: substrait.ReadConsumerEmbeddedTAE,
		TTL: time.Minute, ReadOnly: true,
	})
	require.NoError(t, err)
	protector.failUnregister = true
	var closes atomic.Int32
	runtime := &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedTAE,
		Backend: &siriusEmbeddedBackendStub{close: func(context.Context) error {
			closes.Add(1)
			return nil
		}},
		Leases: leases, LeaseCapability: siriusRuntimeTestCapabilityFor(t, leases),
		DataDir: t.TempDir(), LeaseTTL: time.Minute, CleanupTimeout: time.Second,
	}
	owner := &SiriusReadPlan{ReadRefs: admitted.ReadRefs, LeaseExpiresAt: admitted.ExpiresAt}
	err = runtime.abortEmbeddedAdmittedRead(context.Background(), owner, errors.New("descriptor invariant"))
	require.ErrorContains(t, err, "descriptor invariant")
	require.ErrorContains(t, err, "test unregister failure")
	require.Equal(t, int32(1), closes.Load(), "failed local release seals native admission")

	protector.failUnregister = false
	require.NoError(t, owner.Release(context.Background(), leases), "durable lease remains retryable")
}

func TestRecoverAdmittedReadReleasesOrRetainsRetryableOwner(t *testing.T) {
	require.Error(t, (*SiriusRuntime)(nil).recoverAdmittedRead(context.Background(), 0, nil, nil))
	query := &planpb.Query{
		StmtType: planpb.Query_SELECT, Steps: []int32{0}, Headings: []string{"a"},
		Nodes: []*planpb.Node{{
			NodeId: 0, NodeType: planpb.Node_TABLE_SCAN,
			ObjRef: &planpb.ObjectRef{Obj: 42, ObjName: "t"},
			TableDef: &planpb.TableDef{DbId: 7, TblId: 42, Version: 3, Name: "t", TableType: "r", Cols: []*planpb.ColDef{{
				Name: "a", ColId: 11, Seqnum: 5, Typ: planpb.Type{Id: int32(types.T_int64)},
			}}},
		}},
	}
	candidate, err := substrait.Export(query)
	require.NoError(t, err)
	protector := &siriusRuntimeTestProtector{}
	leases := substrait.NewLeaseManager(1, protector)
	admitted, err := substrait.AdmitReads(context.Background(), substrait.AdmissionRequest{
		Candidate: candidate, Provider: siriusRuntimeTestProvider{schema: candidate.Reads()[0].Schema}, Leases: leases,
		AccountID: 1, QueryID: bytes.Repeat([]byte{'q'}, 16), SnapshotTS: make([]byte, 12),
		AuthorizedClientSPKIHash: bytes.Repeat([]byte{1}, 32), TTL: time.Minute, ReadOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, leases.PendingExecutions(), 1)
	runtime := &SiriusRuntime{Backend: NewSiriusFlightBackend(&sidecarflight.Runtime{}), Leases: leases, CleanupTimeout: time.Second}
	plan := &SiriusReadPlan{ReadRefs: admitted.ReadRefs}
	require.NoError(t, runtime.recoverAdmittedRead(nil, 1, bytes.Repeat([]byte{'q'}, 16), plan))
	require.Empty(t, leases.PendingExecutions())

	admitted, err = substrait.AdmitReads(context.Background(), substrait.AdmissionRequest{
		Candidate: candidate, Provider: siriusRuntimeTestProvider{schema: candidate.Reads()[0].Schema}, Leases: leases,
		AccountID: 1, QueryID: bytes.Repeat([]byte{'r'}, 16), SnapshotTS: make([]byte, 12),
		AuthorizedClientSPKIHash: bytes.Repeat([]byte{1}, 32), TTL: time.Minute, ReadOnly: true,
	})
	require.NoError(t, err)
	protector.failUnregister = true
	err = runtime.recoverAdmittedRead(context.Background(), 0, nil, &SiriusReadPlan{ReadRefs: admitted.ReadRefs})
	require.ErrorContains(t, err, "test unregister failure")
	require.ErrorContains(t, err, "invalid replayed execution")
	require.Len(t, leases.PendingExecutions(), 1)
	protector.failUnregister = false
	require.NoError(t, releaseReadRefs(context.Background(), leases, admitted.ReadRefs))
}

func TestSiriusCompileFastRejections(t *testing.T) {
	require.True(t, siriusStatementEligible(&tree.Select{}))
	require.False(t, siriusStatementEligible(&tree.Select{IsPerform: true}))
	require.False(t, siriusStatementEligible(&tree.Select{Ep: &tree.ExportParam{}}))
	require.False(t, siriusStatementEligible(sqlCalcFoundRowsTestStatement()))
	require.False(t, siriusStatementEligible(nil))
	require.False(t, siriusPlanEligible(&planpb.Plan{Plan: &planpb.Plan_Query{Query: &planpb.Query{
		UnresolvedIndexHints: []*planpb.UnresolvedIndexHint{{IndexName: "idx_new"}},
	}}}))
	require.True(t, siriusPlanEligible(&planpb.Plan{Plan: &planpb.Plan_Query{Query: &planpb.Query{}}}))

	requested := WithSiriusOffload(context.Background())
	for _, c := range []*Compile{
		nil,
		{},
		{isPrepare: true, stmt: &tree.Select{}},
		{isInternal: true, stmt: &tree.Select{}},
		{stmt: &tree.Select{IsPerform: true}},
	} {
		offloaded, err := c.tryCompileSiriusRead(requested, nil)
		require.NoError(t, err)
		require.False(t, offloaded)
	}
	offloaded, err := (&Compile{}).tryCompileSiriusRead(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, offloaded)

	require.NoError(t, (*siriusReadOwner)(nil).finish(context.Background(), false))
	err = (&Compile{}).runSiriusRead(context.Background(), nil)
	require.ErrorContains(t, err, "missing Sirius execution owner")
}

type siriusAdmissionBackend struct {
	SiriusBackend
	accepting bool
}

func (b *siriusAdmissionBackend) Accepting() bool { return b.accepting }

func TestEmbeddedSiriusAdmissionNeverSilentlyFallsBack(t *testing.T) {
	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	runtime := moruntime.ServiceRuntime(proc.GetService())
	previous, existed := runtime.GetGlobalVariables(SiriusRuntimeKey)
	backend := &siriusAdmissionBackend{accepting: true}
	configured := &SiriusRuntime{Source: SiriusRuntimeEmbeddedMO, Backend: backend, CleanupTimeout: time.Second}
	require.NoError(t, configured.InitEmbeddedAdmission(16))
	runtime.SetGlobalVariables(SiriusRuntimeKey, configured)
	t.Cleanup(func() {
		if existed {
			runtime.SetGlobalVariables(SiriusRuntimeKey, previous)
		} else {
			runtime.CompareAndDeleteGlobalVariables(SiriusRuntimeKey, configured)
		}
	})
	c := &Compile{proc: proc, stmt: &tree.Select{}}
	ctx := WithSiriusOffload(context.Background())
	for _, query := range []*planpb.Plan{nil, {Plan: &planpb.Plan_Query{Query: &planpb.Query{}}}} {
		offloaded, err := c.tryCompileSiriusRead(ctx, query)
		require.False(t, offloaded)
		require.Error(t, err, "an invalid explicitly embedded query must fail closed")
		configured.embeddedAdmission.mu.Lock()
		require.False(t, configured.embeddedAdmission.active,
			"pure plan rejection must not claim embedded admission")
		require.Zero(t, configured.embeddedAdmission.waiters.Len())
		configured.embeddedAdmission.mu.Unlock()
		backend.accepting = false
		offloaded, err = c.tryCompileSiriusRead(ctx, query)
		require.False(t, offloaded)
		require.ErrorContains(t, err, "admission is sealed")
		backend.accepting = true
	}
	offloaded, err := c.tryCompileSiriusRead(context.Background(), nil)
	require.False(t, offloaded)
	require.NoError(t, err)
}

func TestSQLSelectLimitIsMaterializedBeforeSiriusExport(t *testing.T) {
	proc := testutil.NewProcess(t)
	proc.Base.SessionInfo.ApplySQLSelectLimit = true
	proc.SetResolveVariableFunc(func(name string, _, _ bool) (interface{}, error) {
		if name == plan2.SQLSelectLimitVariable {
			return uint64(3), nil
		}
		return nil, nil
	})
	t.Cleanup(proc.Free)

	query := &planpb.Query{
		StmtType: planpb.Query_SELECT, Steps: []int32{0}, Headings: []string{"a"},
		ApplySqlSelectLimit: true,
		Nodes: []*planpb.Node{{
			NodeId: 0, NodeType: planpb.Node_TABLE_SCAN,
			ObjRef: &planpb.ObjectRef{Obj: 42, ObjName: "t"},
			TableDef: &planpb.TableDef{
				DbId: 7, TblId: 42, Version: 3, Name: "t", TableType: "r",
				Cols: []*planpb.ColDef{{
					Name: "a", ColId: 11, Seqnum: 5,
					Typ: planpb.Type{Id: int32(types.T_int64)},
				}},
			},
		}},
	}
	queryPlan := &planpb.Plan{Plan: &planpb.Plan_Query{Query: query}}
	c := &Compile{proc: proc}
	materialization, err := c.materializeSQLSelectLimit(queryPlan)
	require.NoError(t, err)
	require.False(t, query.ApplySqlSelectLimit)
	require.Equal(t, uint64(3), query.Nodes[0].Limit.GetLit().GetU64Val())

	candidate, err := substrait.Export(query)
	require.NoError(t, err)
	wire, err := candidate.Build(map[int32][]byte{0: {1}})
	require.NoError(t, err)
	offloadedPlan := new(spb.Plan)
	require.NoError(t, proto.Unmarshal(wire, offloadedPlan))
	fetch := offloadedPlan.Relations[0].GetRoot().Input.GetFetch()
	require.NotNil(t, fetch)
	require.Equal(t, int64(3), fetch.GetCount())

	materialization.restore()
	require.True(t, query.ApplySqlSelectLimit)
	require.Nil(t, query.Nodes[0].Limit)
}
