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
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/common/mpool"
	moruntime "github.com/matrixorigin/matrixone/pkg/common/runtime"
	"github.com/matrixorigin/matrixone/pkg/container/batch"
	"github.com/matrixorigin/matrixone/pkg/container/types"
	"github.com/matrixorigin/matrixone/pkg/container/vector"
	"github.com/matrixorigin/matrixone/pkg/defines"
	mock_frontend "github.com/matrixorigin/matrixone/pkg/frontend/test"
	"github.com/matrixorigin/matrixone/pkg/objectio"
	planpb "github.com/matrixorigin/matrixone/pkg/pb/plan"
	"github.com/matrixorigin/matrixone/pkg/pb/timestamp"
	"github.com/matrixorigin/matrixone/pkg/perfcounter"
	"github.com/matrixorigin/matrixone/pkg/sql/parsers/tree"
	plan2 "github.com/matrixorigin/matrixone/pkg/sql/plan"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/testutil"
	"github.com/matrixorigin/matrixone/pkg/txn/client"
	"github.com/matrixorigin/matrixone/pkg/vm/engine"
	"github.com/matrixorigin/matrixone/pkg/vm/process"
	"github.com/stretchr/testify/require"
	spb "github.com/substrait-io/substrait-protobuf/go/substraitpb"
	"google.golang.org/protobuf/proto"
)

type siriusInputStub struct {
	push      func(context.Context, uint32, []SiriusInputVector) error
	acquire   func(context.Context, uint64) (SiriusInputLease, error)
	notNeeded error
}

func (s *siriusInputStub) Acquire(ctx context.Context, bytes uint64) (SiriusInputLease, error) {
	if s.acquire != nil {
		return s.acquire(ctx, bytes)
	}
	return &siriusInputLeaseStub{input: s, capacity: bytes}, nil
}

func (s *siriusInputStub) IsNotNeeded(err error) bool {
	return s.notNeeded != nil && errors.Is(err, s.notNeeded)
}

type siriusInputLeaseStub struct {
	input    *siriusInputStub
	capacity uint64
	release  func() error
}

func (l *siriusInputLeaseStub) Capacity() uint64 { return l.capacity }
func (l *siriusInputLeaseStub) Publish(ctx context.Context, rows uint32, vectors []SiriusInputVector) error {
	if l.input.push == nil {
		return nil
	}
	return l.input.push(ctx, rows, vectors)
}
func (l *siriusInputLeaseStub) Release() error {
	if l.release != nil {
		return l.release()
	}
	return nil
}

func TestSiriusProducerGroupSingleRunAndSharedTerminal(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(error) func(context.Context) error
		want string
	}{
		{
			name: "error",
			run:  func(want error) func(context.Context) error { return func(context.Context) error { return want } },
			want: "pipeline failed",
		},
		{
			name: "panic",
			run: func(error) func(context.Context) error {
				return func(context.Context) error { panic("pipeline panic") }
			},
			want: "producer pipeline panicked: pipeline panic",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := errors.New(test.want)
			group := newSiriusProducerGroup(2)
			var runs atomic.Int32
			group.setRun(func(ctx context.Context) error {
				runs.Add(1)
				return test.run(want)(ctx)
			})
			results := make(chan error, 2)
			go func() { results <- group.join(context.Background(), 1, &siriusInputStub{}) }()
			go func() { results <- group.join(context.Background(), 2, &siriusInputStub{}) }()
			first, second := <-results, <-results
			require.Equal(t, 1, int(runs.Load()))
			require.Equal(t, first.Error(), second.Error())
			require.ErrorContains(t, first, test.want)
		})
	}
}

func TestSiriusProducerGroupCancellationBeforeReadyPreventsStart(t *testing.T) {
	group := newSiriusProducerGroup(2)
	var runs atomic.Int32
	group.setRun(func(context.Context) error { runs.Add(1); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	first := group.join(ctx, 1, &siriusInputStub{})
	second := group.join(context.Background(), 2, &siriusInputStub{})
	require.ErrorIs(t, first, context.Canceled)
	require.ErrorIs(t, second, context.Canceled)
	require.Zero(t, runs.Load())
}

func TestPushSiriusBatchEncodesClassesNullsAndUsesCallerContext(t *testing.T) {
	mp := mpool.MustNewZero()
	flat := vector.NewVec(types.T_int64.ToType())
	require.NoError(t, vector.AppendFixed(flat, int64(7), false, mp))
	require.NoError(t, vector.AppendFixed(flat, int64(9), true, mp))
	constant, err := vector.NewConstFixed(types.T_int32.ToType(), int32(11), 2, mp)
	require.NoError(t, err)
	constantNull := vector.NewConstNull(types.T_varchar.ToType(), 2, mp)
	bat := batch.NewWithSize(3)
	bat.Vecs[0], bat.Vecs[1], bat.Vecs[2] = flat, constant, constantNull
	bat.SetRowCount(2)
	t.Cleanup(func() { bat.Clean(mp) })

	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "producer")
	original := flat.GetData()
	input := &siriusInputStub{push: func(got context.Context, rows uint32, vectors []SiriusInputVector) error {
		require.Equal(t, "producer", got.Value(contextKey{}))
		require.Equal(t, uint32(2), rows)
		require.Len(t, vectors, 3)
		require.Equal(t, SiriusVectorFlat, vectors[0].Class)
		require.Equal(t, SiriusVectorConstant, vectors[1].Class)
		require.Equal(t, SiriusVectorConstantNull, vectors[2].Class)
		require.NotEmpty(t, vectors[0].Data)
		require.Equal(t, &original[0], &vectors[0].Data[0], "ordinary batches use direct data slices")
		require.Equal(t, uint64(2), binary.LittleEndian.Uint64(vectors[0].Nulls))
		require.Empty(t, vectors[2].Data)
		return nil
	}}
	require.NoError(t, pushSiriusBatch(ctx, input, bat, mp))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var pushed atomic.Bool
	err = pushSiriusBatch(canceled, &siriusInputStub{push: func(context.Context, uint32, []SiriusInputVector) error {
		pushed.Store(true)
		return nil
	}}, bat, mp)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, pushed.Load())
}

func TestSiriusOutputNotNeededStopsOnlyItsSink(t *testing.T) {
	mp := mpool.MustNewZero()
	vec := vector.NewVec(types.T_int64.ToType())
	require.NoError(t, vector.AppendFixed(vec, int64(7), false, mp))
	bat := batch.NewWithSize(1)
	bat.Vecs[0] = vec
	bat.SetRowCount(1)
	t.Cleanup(func() { bat.Clean(mp) })
	want := errors.New("not needed")
	input := &siriusInputStub{
		notNeeded: want,
		push:      func(context.Context, uint32, []SiriusInputVector) error { return want },
	}
	var stop atomic.Bool
	require.NoError(t, pushSiriusOutputBatch(context.Background(), input, bat, mp, &stop))
	require.True(t, stop.Load())
}

func TestEmbeddedSiriusOutputScopeKeepsDOPBoundedEdge(t *testing.T) {
	direct := &Scope{Magic: Remote, NodeInfo: engine.Node{Addr: "local", Mcpu: 1}}
	c := &Compile{addr: "local", execType: plan2.ExecTypeAP_ONECN}
	require.Same(t, direct, c.outputScope([]*Scope{direct}))

	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	c.proc = proc
	c.anal = new(AnalyzeModule)
	parallel := &Scope{
		Magic: Remote, NodeInfo: engine.Node{Addr: "local", Mcpu: 2},
		Proc: proc.NewNoContextChildProc(0),
	}
	merged := c.outputScope([]*Scope{parallel})
	require.NotSame(t, parallel, merged)
	require.Len(t, merged.Proc.Reg.MergeReceivers, 1)
	_, capacity := process.WaitRegisterChannelState(merged.Proc.Reg.MergeReceivers[0])
	require.Equal(t, 2, capacity)
	ReleaseScopes([]*Scope{merged})
}

func TestSplitSiriusBatchTargetAndSingleRowLimit(t *testing.T) {
	mp := mpool.MustNewZero()
	vec := vector.NewVec(types.T_int64.ToType())
	for i := 0; i < 10; i++ {
		require.NoError(t, vector.AppendFixed(vec, int64(i), false, mp))
	}
	bat := batch.NewWithSize(1)
	bat.Vecs[0] = vec
	bat.SetRowCount(10)
	t.Cleanup(func() { bat.Clean(mp) })

	ranges, err := splitSiriusBatchAt(bat, 40, 64)
	require.NoError(t, err)
	require.Equal(t, []siriusBatchRange{
		{start: 0, end: 4, compact: true},
		{start: 4, end: 8, compact: true},
		{start: 8, end: 10, compact: true},
	}, ranges)
	_, err = splitSiriusBatchAt(bat, 8, 15)
	require.ErrorContains(t, err, "row exceeds native window")
}

func TestSiriusBatchCompactsStaleAreaLargerThanWindow(t *testing.T) {
	mp := mpool.MustNewZero()
	source := vector.NewVec(types.T_blob.ToType())
	payload := make([]byte, 64<<10)
	for i := 0; i < 1025; i++ {
		require.NoError(t, vector.AppendBytes(source, payload, false, mp))
	}
	require.NoError(t, vector.AppendBytes(source, []byte("ok"), false, mp))
	require.Greater(t, len(source.GetArea()), int(siriusInputWindowBytes))
	window, err := source.Window(1025, 1026)
	require.NoError(t, err)
	bat := batch.NewWithSize(1)
	bat.Vecs[0] = window
	bat.SetRowCount(1)
	t.Cleanup(func() {
		bat.Clean(mp)
		source.Free(mp)
	})

	ranges, err := splitSiriusBatch(bat)
	require.NoError(t, err)
	require.Equal(t, []siriusBatchRange{{start: 0, end: 1, compact: true}}, ranges)
	vectors, release, err := encodeSiriusBatchRange(bat, 0, 1, true, mp)
	require.NoError(t, err)
	defer release()
	require.Len(t, vectors, 1)
	require.Empty(t, vectors[0].Area)
	require.Less(t, len(vectors[0].Data), int(siriusInputTargetBytes))

	baseline := mp.CurrNB()
	group := newSiriusProducerGroup(1)
	group.setRun(func(ctx context.Context) error {
		return pushSiriusBatch(ctx, &siriusInputStub{push: func(context.Context, uint32, []SiriusInputVector) error {
			panic("push panic")
		}}, bat, mp)
	})
	err = group.join(context.Background(), 1, &siriusInputStub{})
	require.ErrorContains(t, err, "producer pipeline panicked: push panic")
	require.Equal(t, baseline, mp.CurrNB(), "panicking Push must release compact range clones")

	constantWindow, err := source.Window(1025, 1026)
	require.NoError(t, err)
	constantWindow.SetClass(vector.CONSTANT)
	constantBatch := batch.NewWithSize(1)
	constantBatch.Vecs[0] = constantWindow
	constantBatch.SetRowCount(1)
	defer constantBatch.Clean(mp)
	constantRanges, err := splitSiriusBatch(constantBatch)
	require.NoError(t, err)
	require.True(t, constantRanges[0].compact)
	constantVectors, constantRelease, err := encodeSiriusBatchRange(constantBatch, 0, 1, true, mp)
	require.NoError(t, err)
	defer constantRelease()
	require.Equal(t, SiriusVectorConstant, constantVectors[0].Class)
	require.Empty(t, constantVectors[0].Area, "constant varlena must not retain unrelated stale area")
}

func TestSiriusConstVarlenaCompactionUsesOnePhysicalRowAcrossRanges(t *testing.T) {
	mp := mpool.MustNewZero()
	source := vector.NewVec(types.T_blob.ToType())
	payload := make([]byte, 64)
	for i := 0; i < 128; i++ {
		require.NoError(t, vector.AppendBytes(source, payload, false, mp))
	}
	constant, err := source.Window(127, 128)
	require.NoError(t, err)
	constant.SetClass(vector.CONSTANT)
	flat := vector.NewVec(types.T_int64.ToType())
	for i := 0; i < 40; i++ {
		require.NoError(t, vector.AppendFixed(flat, int64(i), i%3 == 0, mp))
	}
	bat := batch.NewWithSize(2)
	bat.Vecs[0], bat.Vecs[1] = constant, flat
	bat.SetRowCount(40)
	t.Cleanup(func() {
		bat.Clean(mp)
		source.Free(mp)
	})

	ranges, err := splitSiriusBatchAt(bat, 256, 512)
	require.NoError(t, err)
	require.Greater(t, len(ranges), 1)
	baseline := mp.CurrNB()
	for _, rows := range ranges {
		require.True(t, rows.compact)
		vectors, release, encodeErr := encodeSiriusBatchRange(
			bat, rows.start, rows.end, rows.compact, mp)
		require.NoError(t, encodeErr)
		require.Equal(t, SiriusVectorConstant, vectors[0].Class)
		require.Len(t, vectors[0].Data, types.VarlenaSize)
		require.Equal(t, payload, vectors[0].Area)
		release()
		require.Equal(t, baseline, mp.CurrNB())
	}
}

func TestSiriusInputCreditPrecedesPayloadMaterialization(t *testing.T) {
	mp := mpool.MustNewZero()
	vec := vector.NewVec(types.T_blob.ToType())
	payload := make([]byte, int(siriusInputWindowBytes)-types.VarlenaSize-8-4096)
	require.NoError(t, vector.AppendBytes(vec, payload, false, mp))
	bat := batch.NewWithSize(1)
	bat.Vecs[0] = vec
	bat.SetRowCount(1)
	t.Cleanup(func() { bat.Clean(mp) })
	baseline := mp.CurrNB()

	t.Run("blocked then granted", func(t *testing.T) {
		requested := make(chan uint64, 1)
		grant := make(chan struct{})
		var published, released atomic.Int32
		var input *siriusInputStub
		input = &siriusInputStub{
			push: func(context.Context, uint32, []SiriusInputVector) error {
				published.Add(1)
				return nil
			},
			acquire: func(ctx context.Context, bytes uint64) (SiriusInputLease, error) {
				requested <- bytes
				select {
				case <-grant:
					return &siriusInputLeaseStub{
						input: input, capacity: bytes,
						release: func() error { released.Add(1); return nil },
					}, nil
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			},
		}
		result := make(chan error, 1)
		go func() { result <- pushSiriusBatch(context.Background(), input, bat, mp) }()
		reserved := <-requested
		require.Greater(t, reserved, siriusInputTargetBytes)
		require.Equal(t, baseline, mp.CurrNB(), "CloneWindow must wait behind native credit")
		require.Zero(t, published.Load(), "null/payload encoding must not reach publication before credit")
		close(grant)
		require.NoError(t, <-result)
		require.Equal(t, int32(1), published.Load())
		require.Equal(t, int32(1), released.Load())
		require.Equal(t, baseline, mp.CurrNB())
	})

	t.Run("cancel or native hard rejection allocates nothing", func(t *testing.T) {
		for _, reject := range []bool{false, true} {
			entered := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			input := &siriusInputStub{acquire: func(ctx context.Context, bytes uint64) (SiriusInputLease, error) {
				close(entered)
				if reject {
					return nil, moerr.NewInvalidInputNoCtx("native rounded input window exhausted")
				}
				<-ctx.Done()
				return nil, context.Cause(ctx)
			}}
			result := make(chan error, 1)
			go func() { result <- pushSiriusBatch(ctx, input, bat, mp) }()
			<-entered
			if !reject {
				cancel()
			}
			require.Error(t, <-result)
			cancel()
			require.Equal(t, baseline, mp.CurrNB())
		}
	})
}

type siriusEmbeddedBackendStub struct {
	prepare func(context.Context, SiriusPrepareRequest) (SiriusExecution, error)
	close   func(context.Context) error
}

type siriusEmbeddedTAETestRelation struct {
	*mock_frontend.MockRelation
	tableDef *planpb.TableDef
	visitErr error
}

func (*siriusEmbeddedTAETestRelation) CanVisitSnapshotLocally() (bool, error) { return true, nil }
func (r *siriusEmbeddedTAETestRelation) GetTableDef(context.Context) *planpb.TableDef {
	return r.tableDef
}
func (r *siriusEmbeddedTAETestRelation) VisitSnapshotObjects(
	context.Context,
	types.TS,
	func(objectio.ObjectStats, bool) error,
) error {
	return r.visitErr
}
func (*siriusEmbeddedTAETestRelation) HasSnapshotTombstones(
	context.Context,
	int,
	types.TS,
) (bool, error) {
	return false, nil
}
func (*siriusEmbeddedTAETestRelation) StarCount(context.Context) (uint64, error) {
	return 0, nil
}

func (s *siriusEmbeddedBackendStub) Prepare(ctx context.Context, req SiriusPrepareRequest) (SiriusExecution, error) {
	return s.prepare(ctx, req)
}
func (*siriusEmbeddedBackendStub) Reconcile(uint64, []byte, func(context.Context) error) error {
	return nil
}
func (s *siriusEmbeddedBackendStub) Close(ctx context.Context) error {
	if s.close != nil {
		return s.close(ctx)
	}
	return nil
}
func (*siriusEmbeddedBackendStub) CanFallbackBeforeVisibility(error) bool {
	return false
}

func siriusEmbeddedCompileTestPlan() *planpb.Plan {
	return &planpb.Plan{Plan: &planpb.Plan_Query{Query: &planpb.Query{
		StmtType: planpb.Query_SELECT,
		Steps:    []int32{0},
		Headings: []string{"a"},
		Nodes: []*planpb.Node{{
			NodeId: 0, NodeType: planpb.Node_TABLE_SCAN, Stats: &planpb.Stats{Dop: 1},
			ObjRef: &planpb.ObjectRef{DbName: "db", SchemaName: "db", ObjName: "t", Obj: 42},
			TableDef: &planpb.TableDef{
				DbId: 1, DbName: "db", Name: "t", TblId: 42, TableType: "r",
				Cols: []*planpb.ColDef{{
					Name: "a", ColId: 7, Seqnum: 3,
					Typ: planpb.Type{Id: int32(types.T_int64)},
				}},
			},
		}},
	}}}
}

func TestEmbeddedSiriusPreparesBeforeOpeningRelations(t *testing.T) {
	ctrl := gomock.NewController(t)
	workspace := mock_frontend.NewMockWorkspace(ctrl)
	workspace.EXPECT().Readonly().Return(true).AnyTimes()
	workspace.EXPECT().WriteOffset().Return(uint64(0)).AnyTimes()
	workspace.EXPECT().GetSnapshotWriteOffset().Return(0).AnyTimes()
	workspace.EXPECT().GetHaveDDL().Return(false).AnyTimes()
	txnOp := mock_frontend.NewMockTxnOperator(ctrl)
	txnOp.EXPECT().GetWorkspace().Return(workspace).AnyTimes()
	txnOp.EXPECT().SnapshotTS().Return(timestamp.Timestamp{PhysicalTime: 42, LogicalTime: 3}).AnyTimes()
	storage := mock_frontend.NewMockEngine(ctrl)
	database := mock_frontend.NewMockDatabase(ctrl)
	relation := mock_frontend.NewMockRelation(ctrl)
	var relationOpens atomic.Int32
	storage.EXPECT().Database(gomock.Any(), "db", gomock.Any()).DoAndReturn(
		func(context.Context, string, client.TxnOperator) (engine.Database, error) {
			relationOpens.Add(1)
			return database, nil
		}).AnyTimes()
	database.EXPECT().Relation(gomock.Any(), "t", gomock.Any()).Return(relation, nil).AnyTimes()

	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	proc.Base.TxnOperator = txnOp
	plan := siriusEmbeddedCompileTestPlan()
	var cleanups atomic.Int32
	execution := &siriusExecutionStub{
		run: func(context.Context, *mpool.MPool, *perfcounter.CounterSet, func(*batch.Batch, *perfcounter.CounterSet) error) error {
			return nil
		},
		cleanup: func(context.Context, bool) error { cleanups.Add(1); return nil },
	}
	backend := &siriusEmbeddedBackendStub{prepare: func(_ context.Context, req SiriusPrepareRequest) (SiriusExecution, error) {
		require.Zero(t, relationOpens.Load(), "native Prepare must precede relation access")
		require.Len(t, req.Reads, 1)
		require.NotNil(t, req.Reads[0].Producer)
		require.Equal(t, uint64(1), req.Reads[0].BindingID)
		require.Equal(t, [12]byte{3, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0}, req.Snapshot)
		return execution, nil
	}}
	runtime := &SiriusRuntime{Source: SiriusRuntimeEmbeddedMO, Backend: backend, CleanupTimeout: time.Second}
	require.NoError(t, runtime.InitEmbeddedAdmission(16))
	serviceRuntime := moruntime.ServiceRuntime(proc.GetService())
	serviceRuntime.SetGlobalVariables(SiriusRuntimeKey, runtime)
	t.Cleanup(func() { serviceRuntime.CompareAndDeleteGlobalVariables(SiriusRuntimeKey, runtime) })
	c := allocateNewCompile(proc)
	c.e, c.addr, c.ncpu, c.stmt, c.pn = storage, "local", 1, &tree.Select{}, plan
	offloaded, err := c.tryCompileSiriusRead(
		WithSiriusOffload(defines.AttachAccountId(context.Background(), 7)), plan,
	)
	require.NoError(t, err)
	require.True(t, offloaded)
	require.Positive(t, relationOpens.Load())
	require.Len(t, c.scopes, 1)
	c.Release()
	require.Equal(t, int32(1), cleanups.Load())
}

func TestEmbeddedTAEPlanAndDescriptorsPrecedeStorageAdmission(t *testing.T) {
	ctrl := gomock.NewController(t)
	workspace := mock_frontend.NewMockWorkspace(ctrl)
	workspace.EXPECT().Readonly().Return(true).AnyTimes()
	workspace.EXPECT().WriteOffset().Return(uint64(0)).AnyTimes()
	workspace.EXPECT().GetSnapshotWriteOffset().Return(0).AnyTimes()
	txnOp := mock_frontend.NewMockTxnOperator(ctrl)
	txnOp.EXPECT().GetWorkspace().Return(workspace).AnyTimes()
	txnOp.EXPECT().SnapshotTS().Return(timestamp.Timestamp{PhysicalTime: 42, LogicalTime: 3}).AnyTimes()
	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	proc.Base.TxnOperator = txnOp
	queryPlan := siriusEmbeddedCompileTestPlan()
	node := queryPlan.GetQuery().Nodes[0]
	node.TableDef.Cols = append(node.TableDef.Cols, &planpb.ColDef{
		Name: "b", ColId: 8, Seqnum: 4, Typ: planpb.Type{Id: int32(types.T_int32)},
	})
	node.ProjectList = []*planpb.Expr{{
		Typ:  node.TableDef.Cols[0].Typ,
		Expr: &planpb.Expr_Col{Col: &planpb.ColRef{RelPos: 0, ColPos: 0}},
	}}
	c := &Compile{proc: proc}
	plan, err := c.buildSiriusEmbeddedTAEPlan(
		defines.AttachAccountId(context.Background(), 7), queryPlan)
	require.NoError(t, err)
	require.Len(t, plan.request.QueryID, 16, "statement identity stays opaque rather than hex-expanded")
	require.Len(t, plan.request.Reads, 1)
	read := plan.request.Reads[0]
	require.Equal(t, uint64(1), read.BindingID)
	require.Equal(t, "db", read.Database)
	require.Equal(t, "t", read.Table)
	require.Equal(t, "db", read.Schema)
	require.Nil(t, read.Producer)
	require.Empty(t, read.TAEManifest)
	require.Len(t, read.Columns, 2, "TAE descriptors retain the physical scan schema")
	require.Equal(t, []string{"a", "b"}, []string{read.Columns[0].Name, read.Columns[1].Name})
	require.Equal(t, []uint64{7, 8}, []uint64{read.Columns[0].PhysicalID, read.Columns[1].PhysicalID})

	wire := new(spb.Plan)
	require.NoError(t, proto.Unmarshal(plan.request.Plan, wire))
	project := wire.Relations[0].GetRoot().GetInput().GetProject()
	require.NotNil(t, project)
	named := project.GetInput().GetRead().GetNamedTable()
	require.Equal(t, []string{"__sirius_embedded_v1", "1"}, named.GetNames())
}

func TestEmbeddedTAEAdmissionPreparesNativeWithoutMOProducer(t *testing.T) {
	for _, test := range []struct {
		name         string
		prepareFail  bool
		nilExecution bool
		relationFail bool
		admitFail    bool
	}{
		{name: "execution owns release"},
		{name: "native prepare failure releases", prepareFail: true},
		{name: "illegal nil execution seals runtime", nilExecution: true},
		{name: "relation failure releases admission", relationFail: true},
		{name: "storage admission failure releases admission", admitFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			workspace := mock_frontend.NewMockWorkspace(ctrl)
			workspace.EXPECT().Readonly().Return(true).AnyTimes()
			workspace.EXPECT().WriteOffset().Return(uint64(0)).AnyTimes()
			workspace.EXPECT().GetSnapshotWriteOffset().Return(0).AnyTimes()
			workspace.EXPECT().GetHaveDDL().Return(false).AnyTimes()
			txnOp := mock_frontend.NewMockTxnOperator(ctrl)
			txnOp.EXPECT().GetWorkspace().Return(workspace).AnyTimes()
			txnOp.EXPECT().SnapshotTS().Return(timestamp.Timestamp{PhysicalTime: 42, LogicalTime: 3}).AnyTimes()

			queryPlan := siriusEmbeddedCompileTestPlan()
			storage := mock_frontend.NewMockEngine(ctrl)
			database := mock_frontend.NewMockDatabase(ctrl)
			relationMock := mock_frontend.NewMockRelation(ctrl)
			relation := &siriusEmbeddedTAETestRelation{
				MockRelation: relationMock,
				tableDef:     queryPlan.GetQuery().Nodes[0].TableDef,
			}
			if test.admitFail {
				relation.visitErr = errors.New("snapshot visit failed")
			}
			var relationOpens atomic.Int32
			if test.relationFail {
				storage.EXPECT().Database(gomock.Any(), "db", gomock.Any()).DoAndReturn(
					func(context.Context, string, client.TxnOperator) (engine.Database, error) {
						relationOpens.Add(1)
						return nil, errors.New("relation open failed")
					})
			} else {
				storage.EXPECT().Database(gomock.Any(), "db", gomock.Any()).DoAndReturn(
					func(context.Context, string, client.TxnOperator) (engine.Database, error) {
						relationOpens.Add(1)
						return database, nil
					})
				database.EXPECT().Relation(gomock.Any(), "t", gomock.Any()).Return(relation, nil)
			}

			proc := testutil.NewProcess(t)
			t.Cleanup(proc.Free)
			proc.Base.TxnOperator = txnOp
			leases := substrait.NewPersistentLeaseManager(
				1, &siriusRuntimeTestProtector{}, siriusDurableJournalStub{})
			require.NoError(t, leases.Replay(context.Background()))
			var releases atomic.Int32
			var closes atomic.Int32
			var prepares atomic.Int32
			var request SiriusPrepareRequest
			backend := &siriusEmbeddedBackendStub{close: func(context.Context) error {
				closes.Add(1)
				return nil
			}, prepare: func(ctx context.Context, req SiriusPrepareRequest) (SiriusExecution, error) {
				prepares.Add(1)
				request = req
				require.Equal(t, int32(1), relationOpens.Load(), "storage admission precedes native preparation")
				require.Len(t, req.Reads, 1)
				require.Nil(t, req.Reads[0].Producer)
				require.NotEmpty(t, req.Reads[0].TAEManifest)
				require.Equal(t, "/shared/tae", req.Reads[0].DataRoot)
				require.False(t, req.Deadline.IsZero())
				require.NotNil(t, req.Release)
				if test.prepareFail {
					require.NoError(t, req.Release(ctx))
					releases.Add(1)
					return nil, errors.New("native prepare failed")
				}
				if test.nilExecution {
					return nil, nil
				}
				return &siriusExecutionStub{
					run: func(context.Context, *mpool.MPool, *perfcounter.CounterSet, func(*batch.Batch, *perfcounter.CounterSet) error) error {
						return nil
					},
					cleanup: func(cleanup context.Context, _ bool) error {
						releases.Add(1)
						return req.Release(cleanup)
					},
				}, nil
			}}
			runtime := &SiriusRuntime{
				Source: SiriusRuntimeEmbeddedTAE, Backend: backend, Leases: leases,
				DataDir: "/shared/tae", LeaseTTL: time.Minute, CleanupTimeout: time.Second,
			}
			require.NoError(t, runtime.InitEmbeddedAdmission(16))
			serviceRuntime := moruntime.ServiceRuntime(proc.GetService())
			serviceRuntime.SetGlobalVariables(SiriusRuntimeKey, runtime)
			t.Cleanup(func() { serviceRuntime.CompareAndDeleteGlobalVariables(SiriusRuntimeKey, runtime) })
			c := allocateNewCompile(proc)
			c.e, c.addr, c.ncpu, c.stmt, c.pn = storage, "local", 1, &tree.Select{}, queryPlan
			offloaded, err := c.tryCompileSiriusRead(
				WithSiriusOffload(defines.AttachAccountId(context.Background(), 7)), queryPlan,
			)
			if test.relationFail || test.admitFail {
				require.False(t, offloaded)
				if test.relationFail {
					require.ErrorContains(t, err, "relation open failed")
				} else {
					require.ErrorContains(t, err, "snapshot visit failed")
				}
				require.Zero(t, prepares.Load())
				permit, acquireErr := runtime.acquireEmbeddedAdmission(context.Background())
				require.NoError(t, acquireErr, "pre-Prepare failure must release its permit")
				permit.release()
				c.Release()
				return
			}
			if test.prepareFail {
				require.False(t, offloaded)
				require.ErrorContains(t, err, "native prepare failed")
				require.Equal(t, int32(1), releases.Load())
				require.Nil(t, c.siriusRead)
				permit, acquireErr := runtime.acquireEmbeddedAdmission(context.Background())
				require.NoError(t, acquireErr, "ordinary Prepare failure must release its permit")
				permit.release()
				c.Release()
				return
			}
			if test.nilExecution {
				require.False(t, offloaded)
				require.ErrorContains(t, err, "returned no execution")
				require.Zero(t, closes.Load(), "contract failure seals admission without racing backend cleanup")
				require.False(t, runtime.embeddedAdmission.accepting())
				require.Zero(t, releases.Load(), "compiler must not duplicate backend-owned release")
				require.NoError(t, request.Release(context.Background()), "backend retry owner remains usable")
				c.Release()
				return
			}
			require.NoError(t, err)
			require.True(t, offloaded)
			require.Empty(t, c.scopes, "direct TAE never compiles an MO producer")
			require.Nil(t, request.Reads[0].Producer)
			c.Release()
			require.Equal(t, int32(1), releases.Load())
		})
	}
}

func TestEmbeddedSiriusRejectsWritableSnapshotBeforePrepare(t *testing.T) {
	ctrl := gomock.NewController(t)
	workspace := mock_frontend.NewMockWorkspace(ctrl)
	workspace.EXPECT().Readonly().Return(false).Times(2)
	txnOp := mock_frontend.NewMockTxnOperator(ctrl)
	txnOp.EXPECT().GetWorkspace().Return(workspace).AnyTimes()
	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	proc.Base.TxnOperator = txnOp
	c := &Compile{proc: proc}
	_, err := c.buildSiriusEmbeddedPlan(
		defines.AttachAccountId(context.Background(), 7), siriusEmbeddedCompileTestPlan())
	require.ErrorContains(t, err, "read-only snapshot without prior writes")
	_, err = c.buildSiriusEmbeddedTAEPlan(
		defines.AttachAccountId(context.Background(), 7), siriusEmbeddedCompileTestPlan())
	require.ErrorContains(t, err, "read-only snapshot without prior writes")
}

func TestEmbeddedSiriusCancellationJoinsBeforeRelease(t *testing.T) {
	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	c := allocateNewCompile(proc)
	started := make(chan struct{})
	joined := make(chan struct{})
	var cleanups atomic.Int32
	execution := &siriusExecutionStub{
		run: func(ctx context.Context, _ *mpool.MPool, _ *perfcounter.CounterSet, _ func(*batch.Batch, *perfcounter.CounterSet) error) error {
			close(started)
			<-ctx.Done()
			close(joined)
			return context.Cause(ctx)
		},
		cleanup: func(context.Context, bool) error {
			select {
			case <-joined:
			default:
				return errors.New("cleanup ran before producer join")
			}
			cleanups.Add(1)
			return nil
		},
	}
	owner := newSiriusEmbeddedReadOwner(execution, &SiriusRuntime{
		Source: SiriusRuntimeEmbeddedMO, CleanupTimeout: time.Second,
	}, nil)
	c.siriusRead = owner
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- c.runSiriusRead(ctx, func(mpool.AllocationAccountTerminalSnapshot) {}) }()
	<-started
	cancel()
	err := <-result
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, int32(1), cleanups.Load())
	c.siriusRead = nil
	c.Release()
}
