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
	"github.com/matrixorigin/matrixone/pkg/common/mpool"
	moruntime "github.com/matrixorigin/matrixone/pkg/common/runtime"
	"github.com/matrixorigin/matrixone/pkg/container/batch"
	"github.com/matrixorigin/matrixone/pkg/container/types"
	"github.com/matrixorigin/matrixone/pkg/container/vector"
	"github.com/matrixorigin/matrixone/pkg/defines"
	mock_frontend "github.com/matrixorigin/matrixone/pkg/frontend/test"
	planpb "github.com/matrixorigin/matrixone/pkg/pb/plan"
	"github.com/matrixorigin/matrixone/pkg/pb/timestamp"
	"github.com/matrixorigin/matrixone/pkg/perfcounter"
	"github.com/matrixorigin/matrixone/pkg/sql/parsers/tree"
	plan2 "github.com/matrixorigin/matrixone/pkg/sql/plan"
	"github.com/matrixorigin/matrixone/pkg/testutil"
	"github.com/matrixorigin/matrixone/pkg/txn/client"
	"github.com/matrixorigin/matrixone/pkg/vm/engine"
	"github.com/matrixorigin/matrixone/pkg/vm/process"
	"github.com/stretchr/testify/require"
)

type siriusInputStub struct {
	push      func(context.Context, uint32, []SiriusInputVector) error
	notNeeded error
}

func (s *siriusInputStub) Push(ctx context.Context, rows uint32, vectors []SiriusInputVector) error {
	if s.push == nil {
		return nil
	}
	return s.push(ctx, rows, vectors)
}

func (s *siriusInputStub) IsNotNeeded(err error) bool {
	return s.notNeeded != nil && errors.Is(err, s.notNeeded)
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

type siriusEmbeddedBackendStub struct {
	prepare func(context.Context, SiriusPrepareRequest) (SiriusExecution, error)
}

func (s *siriusEmbeddedBackendStub) Prepare(ctx context.Context, req SiriusPrepareRequest) (SiriusExecution, error) {
	return s.prepare(ctx, req)
}
func (*siriusEmbeddedBackendStub) Reconcile(uint64, []byte, func(context.Context) error) error {
	return nil
}
func (*siriusEmbeddedBackendStub) Close(context.Context) error { return nil }
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
	runtime := &SiriusRuntime{EmbeddedMO: true, Backend: backend, CleanupTimeout: time.Second}
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

func TestEmbeddedSiriusRejectsWritableSnapshotBeforePrepare(t *testing.T) {
	ctrl := gomock.NewController(t)
	workspace := mock_frontend.NewMockWorkspace(ctrl)
	workspace.EXPECT().Readonly().Return(false)
	txnOp := mock_frontend.NewMockTxnOperator(ctrl)
	txnOp.EXPECT().GetWorkspace().Return(workspace).AnyTimes()
	proc := testutil.NewProcess(t)
	t.Cleanup(proc.Free)
	proc.Base.TxnOperator = txnOp
	c := &Compile{proc: proc}
	_, err := c.buildSiriusEmbeddedPlan(
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
	owner := newSiriusEmbeddedReadOwner(execution, &SiriusRuntime{CleanupTimeout: time.Second})
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
