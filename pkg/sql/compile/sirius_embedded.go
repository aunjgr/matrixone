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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/common/mpool"
	"github.com/matrixorigin/matrixone/pkg/container/batch"
	"github.com/matrixorigin/matrixone/pkg/container/types"
	"github.com/matrixorigin/matrixone/pkg/container/vector"
	"github.com/matrixorigin/matrixone/pkg/defines"
	planpb "github.com/matrixorigin/matrixone/pkg/pb/plan"
	"github.com/matrixorigin/matrixone/pkg/perfcounter"
	"github.com/matrixorigin/matrixone/pkg/sql/colexec/output"
	plan2 "github.com/matrixorigin/matrixone/pkg/sql/plan"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/vm/engine"
	disttaesidecar "github.com/matrixorigin/matrixone/pkg/vm/engine/disttae/sidecar"
)

const (
	siriusInputTargetBytes uint64 = 32 << 20
	siriusInputWindowBytes uint64 = 64 << 20
	siriusMaxReads                = 16
)

type siriusEmbeddedPlan struct {
	request   SiriusPrepareRequest
	reads     []substrait.EmbeddedMORead
	candidate *substrait.Candidate
	taeReads  []substrait.Read
}

// buildSiriusEmbeddedPlan is pure except for reading the already-open
// transaction snapshot. It neither opens relations nor starts storage readers.
func (c *Compile) buildSiriusEmbeddedPlan(
	ctx context.Context,
	queryPlan *planpb.Plan,
) (*siriusEmbeddedPlan, error) {
	if c == nil || c.proc == nil || queryPlan == nil || queryPlan.GetQuery() == nil {
		return nil, moerr.NewInternalError(ctx, "substrait: embedded compile has no SELECT plan")
	}
	candidate, err := substrait.Export(queryPlan.GetQuery())
	if err != nil {
		return nil, err
	}
	reads, err := candidate.EmbeddedMOReads()
	if err != nil {
		return nil, err
	}
	if len(reads) == 0 || len(reads) > siriusMaxReads {
		return nil, substrait.NotEligible(substrait.EligibilityPlanShape,
			"embedded MO read count is unsupported")
	}

	txnOp := c.proc.GetTxnOperator()
	if txnOp == nil || txnOp.GetWorkspace() == nil ||
		!txnOp.GetWorkspace().Readonly() ||
		txnOp.GetWorkspace().WriteOffset() != 0 ||
		txnOp.GetWorkspace().GetSnapshotWriteOffset() != 0 {
		return nil, substrait.NotEligible(substrait.EligibilityTransaction,
			"embedded MO input requires a read-only snapshot without prior writes")
	}
	snapshotTS := types.TimestampToTS(txnOp.SnapshotTS())
	snapshot, err := snapshotTS.Marshal()
	if err != nil {
		return nil, err
	}
	if len(snapshot) != 12 {
		return nil, moerr.NewInternalErrorNoCtxf(
			"substrait: embedded snapshot has %d bytes, want 12", len(snapshot))
	}
	accountID, err := defines.GetAccountId(ctx)
	if err != nil {
		return nil, err
	}
	statementID := c.proc.GetStmtProfile().GetStmtId()
	queryID := append([]byte(nil), statementID[:]...)
	request := SiriusPrepareRequest{
		AccountID:   uint64(accountID),
		QueryID:     queryID,
		OutputTypes: candidate.OutputTypes(),
		Headings:    append([]string(nil), queryPlan.GetQuery().Headings...),
		Reads:       make([]SiriusReadDescriptor, len(reads)),
	}
	copy(request.Snapshot[:], snapshot)
	bindings := make(map[int32]substrait.EmbeddedReadBinding, len(reads))
	for i, read := range reads {
		bindingID := uint64(i + 1)
		bindings[read.NodeID] = substrait.EmbeddedReadBinding{
			BindingID: bindingID,
			Source:    substrait.EmbeddedReadMO,
		}
		descriptor := &request.Reads[i]
		descriptor.BindingID = bindingID
		descriptor.Database = read.Database
		descriptor.Table = read.Table
		descriptor.Schema = read.Schema
		descriptor.Columns = make([]SiriusReadColumn, len(read.Columns))
		for j, column := range read.Columns {
			descriptor.Columns[j] = SiriusReadColumn{
				Type: column.Type, Name: column.Name,
				PhysicalID: column.PhysicalID, Sequence: column.Sequence,
			}
		}
	}
	request.Plan, err = candidate.BuildEmbedded(bindings)
	if err != nil {
		return nil, err
	}
	return &siriusEmbeddedPlan{request: request, reads: reads}, nil
}

// buildSiriusEmbeddedTAEPlan finishes every pure plan and descriptor decision
// before the caller opens a relation or asks storage to protect a snapshot.
func (c *Compile) buildSiriusEmbeddedTAEPlan(
	ctx context.Context,
	queryPlan *planpb.Plan,
) (*siriusEmbeddedPlan, error) {
	if c == nil || c.proc == nil || queryPlan == nil || queryPlan.GetQuery() == nil {
		return nil, moerr.NewInternalError(ctx, "substrait: embedded TAE compile has no SELECT plan")
	}
	candidate, err := substrait.Export(queryPlan.GetQuery())
	if err != nil {
		return nil, err
	}
	reads := candidate.Reads()
	if len(reads) == 0 || len(reads) > siriusMaxReads {
		return nil, substrait.NotEligible(substrait.EligibilityPlanShape,
			"embedded TAE read count is unsupported")
	}

	txnOp := c.proc.GetTxnOperator()
	if txnOp == nil || txnOp.GetWorkspace() == nil {
		return nil, moerr.NewInternalError(ctx, "substrait: embedded TAE compile has no transaction workspace")
	}
	workspace := txnOp.GetWorkspace()
	if !workspace.Readonly() || workspace.WriteOffset() != 0 || workspace.GetSnapshotWriteOffset() != 0 {
		return nil, substrait.NotEligible(substrait.EligibilityTransaction,
			"embedded TAE input requires a read-only snapshot without prior writes")
	}
	snapshotTS := types.TimestampToTS(txnOp.SnapshotTS())
	snapshot, err := snapshotTS.Marshal()
	if err != nil {
		return nil, err
	}
	if len(snapshot) != 12 {
		return nil, moerr.NewInternalErrorNoCtxf(
			"substrait: embedded TAE snapshot has %d bytes, want 12", len(snapshot))
	}
	accountID, err := defines.GetAccountId(ctx)
	if err != nil {
		return nil, err
	}
	statementID := c.proc.GetStmtProfile().GetStmtId()
	queryID := append([]byte(nil), statementID[:]...)
	request := SiriusPrepareRequest{
		AccountID: uint64(accountID), QueryID: queryID,
		OutputTypes: candidate.OutputTypes(),
		Headings:    append([]string(nil), queryPlan.GetQuery().Headings...),
		Reads:       make([]SiriusReadDescriptor, len(reads)),
	}
	copy(request.Snapshot[:], snapshot)
	bindings := make(map[int32]substrait.EmbeddedReadBinding, len(reads))
	for i, read := range reads {
		bindingID := uint64(i + 1)
		descriptor, descriptorErr := embeddedTAEReadDescriptor(queryPlan.GetQuery(), read, bindingID)
		if descriptorErr != nil {
			return nil, descriptorErr
		}
		request.Reads[i] = descriptor
		bindings[read.NodeID] = substrait.EmbeddedReadBinding{
			BindingID: bindingID,
			Source:    substrait.EmbeddedReadTAE,
		}
	}
	request.Plan, err = candidate.BuildEmbedded(bindings)
	if err != nil {
		return nil, err
	}
	return &siriusEmbeddedPlan{request: request, candidate: candidate, taeReads: reads}, nil
}

func embeddedTAEReadDescriptor(
	query *planpb.Query,
	read substrait.Read,
	bindingID uint64,
) (SiriusReadDescriptor, error) {
	if query == nil || read.NodeID < 0 || int(read.NodeID) >= len(query.Nodes) {
		return SiriusReadDescriptor{}, moerr.NewInternalErrorNoCtx("substrait: embedded TAE scan node is missing")
	}
	node := query.Nodes[read.NodeID]
	if node == nil || node.NodeId != read.NodeID || node.NodeType != planpb.Node_TABLE_SCAN ||
		node.ObjRef == nil || node.TableDef == nil {
		return SiriusReadDescriptor{}, moerr.NewInternalErrorNoCtx("substrait: embedded TAE scan identity is invalid")
	}
	descriptor := SiriusReadDescriptor{
		BindingID: bindingID,
		Database:  node.ObjRef.DbName,
		Table:     node.ObjRef.ObjName,
		Schema:    node.ObjRef.SchemaName,
		Columns:   make([]SiriusReadColumn, 0, len(read.Columns)),
	}
	if descriptor.Database == "" {
		descriptor.Database = node.TableDef.DbName
	}
	if descriptor.Table == "" {
		descriptor.Table = node.TableDef.Name
	}
	for _, column := range node.TableDef.Cols {
		if column == nil {
			return SiriusReadDescriptor{}, moerr.NewInternalErrorNoCtx("substrait: embedded TAE table has a nil column")
		}
		if column.Hidden {
			continue
		}
		position := len(descriptor.Columns)
		if position >= len(read.Columns) || read.Columns[position].ColumnID != column.ColId ||
			read.Columns[position].SequenceNumber != column.Seqnum {
			return SiriusReadDescriptor{}, moerr.NewInternalErrorNoCtx("substrait: embedded TAE physical schema changed during planning")
		}
		descriptor.Columns = append(descriptor.Columns, SiriusReadColumn{
			Type: column.Typ, Name: column.Name,
			PhysicalID: column.ColId, Sequence: column.Seqnum,
		})
	}
	if len(descriptor.Columns) != len(read.Columns) {
		return SiriusReadDescriptor{}, moerr.NewInternalErrorNoCtx("substrait: embedded TAE descriptor width mismatch")
	}
	return descriptor, nil
}

func (c *Compile) tryCompileEmbeddedSiriusRead(
	ctx context.Context,
	queryPlan *planpb.Plan,
	runtime *SiriusRuntime,
) (bool, error) {
	if runtime.Source == SiriusRuntimeEmbeddedTAE {
		return c.tryCompileEmbeddedTAESiriusRead(ctx, queryPlan, runtime)
	}
	if runtime.Source != SiriusRuntimeEmbeddedMO {
		return false, moerr.NewInternalErrorNoCtx("substrait: invalid embedded Sirius read source")
	}
	plan, err := c.buildSiriusEmbeddedPlan(ctx, queryPlan)
	if err != nil {
		return false, err
	}
	c.initSiriusEmbeddedCompile(queryPlan)

	group := newSiriusProducerGroup(len(plan.reads))
	for i := range plan.request.Reads {
		bindingID := plan.request.Reads[i].BindingID
		plan.request.Reads[i].Producer = func(producerCtx context.Context, input SiriusInput) error {
			return group.join(producerCtx, bindingID, input)
		}
	}

	// Native preparation is the admission point. In particular, no relation is
	// opened and no storage reader can start before it succeeds.
	execution, err := runtime.Backend.Prepare(ctx, plan.request)
	if err != nil {
		return false, err
	}
	if execution == nil {
		return false, moerr.NewInternalErrorNoCtx("substrait: embedded preparation returned no execution")
	}
	scopes, err := c.compileSiriusEmbeddedScopes(queryPlan.GetQuery(), plan.reads, group)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeoutCause(
			context.WithoutCancel(ctx), runtime.CleanupTimeout,
			moerr.NewInternalErrorNoCtx("substrait: timed out cleaning up failed embedded compile"),
		)
		defer cancel()
		return false, errors.Join(err, execution.Cleanup(cleanupCtx))
	}
	c.scopes = scopes
	group.setRun(func(runCtx context.Context) error {
		if c.MessageBoard == nil {
			return moerr.NewInternalError(runCtx, "substrait: embedded Sirius execution has no message board")
		}
		callbackDone := make(chan struct{})
		stop := context.AfterFunc(runCtx, func() {
			cause := context.Cause(runCtx)
			if cause == nil {
				cause = context.Canceled
			}
			if c.proc != nil && c.proc.Cancel != nil {
				c.proc.Cancel(cause)
			}
			close(callbackDone)
		})
		defer func() {
			if !stop() {
				<-callbackDone
			}
		}()
		return c.runPipelineAttempt(func() error {
			c.MessageBoard.BeforeRunonce()
			return c.runOnce()
		})
	})
	c.siriusRead = newSiriusEmbeddedReadOwner(execution, runtime)
	return true, nil
}

func (c *Compile) tryCompileEmbeddedTAESiriusRead(
	ctx context.Context,
	queryPlan *planpb.Plan,
	runtime *SiriusRuntime,
) (bool, error) {
	plan, err := c.buildSiriusEmbeddedTAEPlan(ctx, queryPlan)
	if err != nil {
		return false, err
	}

	relations := make(map[uint64]engine.Relation, len(plan.taeReads))
	for _, read := range plan.taeReads {
		node := queryPlan.GetQuery().Nodes[read.NodeID]
		relation, _, _, openErr := c.handleDbRelContext(node, false)
		if openErr != nil {
			return false, moerr.NewInternalErrorf(ctx,
				"substrait: open embedded TAE table %d: %v", read.TableID, openErr)
		}
		relations[read.TableID] = relation
	}
	txnOp := c.proc.GetTxnOperator()
	workspace := txnOp.GetWorkspace()
	provider := &disttaesidecar.SnapshotProvider{
		Relations: relations, MPool: c.proc.Mp(), DataDir: runtime.DataDir,
		TxnOffset: workspace.GetSnapshotWriteOffset(),
	}
	admitted, err := substrait.AdmitReads(ctx, substrait.AdmissionRequest{
		Candidate: plan.candidate, Provider: provider, Leases: runtime.Leases,
		AccountID: plan.request.AccountID, QueryID: plan.request.QueryID,
		SnapshotTS: plan.request.Snapshot[:], Consumer: substrait.ReadConsumerEmbeddedTAE,
		TTL: runtime.LeaseTTL, ReadOnly: workspace.Readonly(),
		PriorWrites: workspace.WriteOffset() != 0 || workspace.GetSnapshotWriteOffset() != 0,
	})
	if err != nil {
		return false, err
	}
	readOwner := &SiriusReadPlan{
		ReadRefs: cloneReadRefs(admitted.ReadRefs), LeaseExpiresAt: admitted.ExpiresAt,
	}
	for i, read := range plan.taeReads {
		metadata, ok := admitted.EmbeddedTAEReads[read.NodeID]
		if !ok || len(metadata.Manifest) == 0 ||
			!bytes.Equal(metadata.CanonicalSchema, read.Schema) {
			cause := moerr.NewInternalErrorNoCtx(
				"substrait: admitted embedded TAE descriptor is unavailable or stale")
			return false, runtime.abortEmbeddedAdmittedRead(ctx, readOwner, cause)
		}
		// AdmitReads lends these bytes until Release. Native Prepare copies them
		// synchronously, after which the execution owner retains only the lease.
		plan.request.Reads[i].TAEManifest = metadata.Manifest
		plan.request.Reads[i].DataRoot = runtime.DataDir
	}
	plan.request.Deadline = admitted.ExpiresAt.Add(-runtime.CleanupTimeout)
	plan.request.Release = func(releaseCtx context.Context) error {
		return readOwner.Release(releaseCtx, runtime.Leases)
	}
	execution, err := runtime.Backend.Prepare(ctx, plan.request)
	if err != nil {
		// Prepare owns Release on every return once called. The embedded bridge
		// retains failed cleanup for retry rather than exposing an unsafe fallback.
		return false, err
	}
	if execution == nil {
		// Prepare owns Release once called, including an invalid nil-success
		// return. Do not race or duplicate the backend's retryable cleanup.
		cause := moerr.NewInternalErrorNoCtx(
			"substrait: embedded TAE preparation returned no execution")
		return false, runtime.sealEmbeddedRuntime(ctx, cause)
	}
	c.siriusRead = newSiriusEmbeddedReadOwner(execution, runtime)
	return true, nil
}

func (c *Compile) initSiriusEmbeddedCompile(queryPlan *planpb.Plan) {
	execType := plan2.GetExecType(queryPlan.GetQuery(), c.getHaveDDL(), c.isPrepare)
	if execType == plan2.ExecTypeAP_MULTICN {
		execType = plan2.ExecTypeAP_ONECN
	}
	c.execType = execType
	ncpu := max(int32(c.ncpu), 1)
	plan2.CalcQueryDOP(queryPlan, ncpu, 1, execType)
	c.initAnalyzeModule(queryPlan.GetQuery())
}

func (c *Compile) compileSiriusEmbeddedScopes(
	query *planpb.Query,
	reads []substrait.EmbeddedMORead,
	group *siriusProducerGroup,
) (roots []*Scope, resultErr error) {
	defer func() {
		if resultErr != nil {
			ReleaseScopes(roots)
			roots = nil
		}
	}()
	for i, read := range reads {
		if read.NodeID < 0 || int(read.NodeID) >= len(query.Nodes) || query.Nodes[read.NodeID] == nil {
			return nil, moerr.NewInternalErrorNoCtx("substrait: embedded scan node is missing")
		}
		node := plan2.DeepCopyNode(query.Nodes[read.NodeID])
		c.appendMetaTables(node.ObjRef)
		node.RuntimeFilterProbeList = nil
		node.RuntimeFilterBuildList = nil
		node.RecvMsgList = nil
		node.AggList = nil
		if len(node.ProjectList) == 0 {
			for position, column := range node.TableDef.Cols {
				if column == nil || column.Hidden {
					continue
				}
				node.ProjectList = append(node.ProjectList, &planpb.Expr{
					Typ:  column.Typ,
					Expr: &planpb.Expr_Col{Col: &planpb.ColRef{RelPos: 0, ColPos: int32(position)}},
				})
			}
		}
		c.setAnalyzeCurrent(nil, int(read.NodeID))
		scans, err := c.compileSiriusLocalTableScan(node)
		if err != nil {
			return nil, err
		}
		scans = c.compileTableScanFiltersAndProjection(node, scans)
		if node.Offset != nil {
			scans = c.compileOffset(node, scans)
		}
		if node.Limit != nil {
			scans = c.compileLimit(node, scans)
		}
		root := c.outputScope(scans)
		bindingID := uint64(i + 1)
		var stop atomic.Bool
		root.setRootOperator(output.NewArgument().WithFunc(
			func(bat *batch.Batch, _ *perfcounter.CounterSet) error {
				if bat == nil {
					return nil
				}
				input := group.input(bindingID)
				if input == nil {
					return moerr.NewInternalErrorNoCtx("substrait: embedded native input is not registered")
				}
				producerCtx := group.context()
				if producerCtx == nil {
					return moerr.NewInternalErrorNoCtx("substrait: embedded producer group is not running")
				}
				return pushSiriusOutputBatch(producerCtx, input, bat, c.proc.Mp(), &stop)
			}).WithBlock(false).WithShouldStop(stop.Load))
		roots = append(roots, root)
	}
	return roots, nil
}

func (c *Compile) compileSiriusLocalTableScan(node *planpb.Node) ([]*Scope, error) {
	if _, _, _, err := c.handleDbRelContext(node, false); err != nil {
		return nil, err
	}
	local := getEngineNode(c)
	local.Addr = c.addr
	if node.Stats != nil && node.Stats.Dop > 0 {
		local.Mcpu = min(local.Mcpu, int(node.Stats.Dop))
	}
	local.Mcpu = normalizeMcpu(local.Mcpu)
	local.CNCNT = 1
	local.CNIDX = 0
	scope, err := c.compileTableScanWithNode(node, local, c.anal.isFirst)
	if err != nil {
		return nil, err
	}
	c.anal.isFirst = false
	return []*Scope{scope}, nil
}

// outputScope places a synchronous callback on this CN and preserves the
// ordinary DOP-bounded connector edge when a scan has parallel readers.
func (c *Compile) outputScope(scopes []*Scope) *Scope {
	if c.IsSingleScope(scopes) &&
		(scopes[0].Magic != Remote || scopes[0].ipAddrMatch(c.addr)) {
		return scopes[0]
	}
	return c.newMergeScope(scopes)
}

type siriusProducerGroup struct {
	mu       sync.Mutex
	expected int
	inputs   map[uint64]SiriusInput
	ready    chan struct{}
	done     chan struct{}
	run      func(context.Context) error
	ctx      context.Context
	started  bool
	terminal bool
	result   error
}

func newSiriusProducerGroup(expected int) *siriusProducerGroup {
	return &siriusProducerGroup{
		expected: expected,
		inputs:   make(map[uint64]SiriusInput, expected),
		ready:    make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (g *siriusProducerGroup) setRun(run func(context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.run = run
}

func (g *siriusProducerGroup) input(bindingID uint64) SiriusInput {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inputs[bindingID]
}

func (g *siriusProducerGroup) context() context.Context {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ctx
}

func (g *siriusProducerGroup) failBeforeStart(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started || g.terminal {
		return
	}
	if err == nil {
		err = context.Canceled
	}
	g.result = err
	g.terminal = true
	close(g.ready)
	close(g.done)
}

func (g *siriusProducerGroup) join(ctx context.Context, bindingID uint64, input SiriusInput) error {
	if input == nil {
		err := moerr.NewInternalErrorNoCtx("substrait: embedded producer has no native input")
		g.failBeforeStart(err)
		<-g.done
		return g.result
	}
	g.mu.Lock()
	if g.terminal {
		g.mu.Unlock()
		<-g.done
		return g.result
	}
	if _, exists := g.inputs[bindingID]; exists || len(g.inputs) >= g.expected {
		g.mu.Unlock()
		err := moerr.NewInternalErrorNoCtx("substrait: duplicate embedded producer")
		g.failBeforeStart(err)
		<-g.done
		return g.result
	}
	g.inputs[bindingID] = input
	if len(g.inputs) == g.expected {
		g.started = true
		g.ctx = ctx
		close(g.ready)
		run := g.run
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					message := fmt.Sprint(recovered)
					if len(message) > 256 {
						message = message[:256]
					}
					g.result = moerr.NewInternalErrorNoCtxf(
						"substrait: embedded producer pipeline panicked: %s", message)
				}
				g.mu.Lock()
				g.terminal = true
				g.mu.Unlock()
				close(g.done)
			}()
			if run == nil {
				g.result = moerr.NewInternalErrorNoCtx("substrait: embedded producer group is not configured")
			} else {
				g.result = run(ctx)
			}
		}()
	}
	g.mu.Unlock()

	select {
	case <-g.ready:
	case <-ctx.Done():
		g.failBeforeStart(context.Cause(ctx))
		<-g.done
		return g.result
	}
	<-g.done
	return g.result
}

type siriusBatchRange struct {
	start, end int
	compact    bool
}

func pushSiriusBatch(
	ctx context.Context,
	input SiriusInput,
	bat *batch.Batch,
	mp *mpool.MPool,
) error {
	if input == nil || bat == nil || len(bat.Vecs) == 0 || bat.RowCount() < 0 || uint64(bat.RowCount()) > math.MaxUint32 {
		return moerr.NewInvalidInputNoCtx("invalid Sirius input batch")
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	ranges, err := splitSiriusBatchContext(ctx, bat, siriusInputTargetBytes, siriusInputWindowBytes)
	if err != nil {
		return err
	}
	for _, rows := range ranges {
		if err = ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		payloadBytes, err := siriusBatchRangePayloadBytes(bat, rows.start, rows.end, rows.compact)
		if err != nil {
			return err
		}
		lease, err := input.Acquire(ctx, payloadBytes)
		if err != nil {
			return err
		}
		err = func() (result error) {
			defer func() { result = errors.Join(result, lease.Release()) }()
			vectors, release, encodeErr := encodeSiriusBatchRange(bat, rows.start, rows.end, rows.compact, mp)
			if encodeErr != nil {
				return encodeErr
			}
			defer release()
			actual, sizeErr := siriusInputVectorsPayloadBytes(vectors)
			if sizeErr != nil {
				return sizeErr
			}
			if actual > payloadBytes || actual > lease.Capacity() {
				return moerr.NewInternalErrorNoCtx("Sirius input encoding exceeded reserved native credit")
			}
			if contextErr := ctx.Err(); contextErr != nil {
				return context.Cause(ctx)
			}
			return lease.Publish(ctx, uint32(rows.end-rows.start), vectors)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// siriusBatchRangePayloadBytes is a size-only pass. Native Acquire remains the
// authoritative hard gate because allocator rounding and descriptor charges
// are owned below this raw payload contract.
func siriusBatchRangePayloadBytes(
	bat *batch.Batch,
	start, end int,
	compact bool,
) (uint64, error) {
	if bat == nil || start < 0 || end <= start || end > bat.RowCount() {
		return 0, moerr.NewInvalidInputNoCtx("invalid Sirius input row range")
	}
	whole := start == 0 && end == bat.RowCount()
	var total uint64
	add := func(bytes uint64) error {
		if bytes > siriusInputWindowBytes-total {
			return moerr.NewInvalidInputNoCtx("Sirius input range exceeds native window")
		}
		total += bytes
		return nil
	}
	for _, source := range bat.Vecs {
		if source == nil || source.IsConstNull() {
			continue
		}
		rows := end - start
		physicalRows := rows
		if source.IsConst() {
			physicalRows = 1
		}
		cloneVarlen := source.GetType().IsVarlen() && (!whole || compact)
		if cloneVarlen {
			if err := add(uint64(physicalRows * source.GetType().TypeSize())); err != nil {
				return 0, err
			}
			descriptors, _ := vector.MustVarlenaRawData(source)
			for row := 0; row < physicalRows; row++ {
				logicalRow := start + row
				if source.IsConst() {
					logicalRow = 0
				}
				if source.IsNull(uint64(logicalRow)) || descriptors[logicalRow].IsSmall() {
					continue
				}
				_, size := descriptors[logicalRow].OffsetLen()
				if err := add(uint64(size)); err != nil {
					return 0, err
				}
			}
		} else {
			dataBytes := uint64(len(source.GetData()))
			if !source.IsConst() && !whole {
				dataBytes = uint64(rows * source.GetType().TypeSize())
			}
			if err := add(dataBytes); err != nil {
				return 0, err
			}
			if err := add(uint64(len(source.GetArea()))); err != nil {
				return 0, err
			}
		}
		if !source.IsConst() {
			if err := add(uint64(((rows + 63) / 64) * 8)); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func siriusInputVectorsPayloadBytes(vectors []SiriusInputVector) (uint64, error) {
	var total uint64
	for _, vector := range vectors {
		for _, data := range [][]byte{vector.Data, vector.Area, vector.Nulls} {
			if uint64(len(data)) > siriusInputWindowBytes-total {
				return 0, moerr.NewInvalidInputNoCtx("Sirius input range exceeds native window")
			}
			total += uint64(len(data))
		}
	}
	return total, nil
}

func pushSiriusOutputBatch(
	ctx context.Context,
	input SiriusInput,
	bat *batch.Batch,
	mp *mpool.MPool,
	stop *atomic.Bool,
) error {
	err := pushSiriusBatch(ctx, input, bat, mp)
	if input != nil && input.IsNotNeeded(err) {
		stop.Store(true)
		return nil
	}
	return err
}

// splitSiriusBatch performs one linear pass over the logical cells. It targets
// 32 MiB raw-payload units and isolates a larger row below the raw 64 MiB
// ceiling. Native Acquire is the exact hard gate because it also owns allocator
// rounding and per-column descriptor charges.
func splitSiriusBatch(bat *batch.Batch) ([]siriusBatchRange, error) {
	return splitSiriusBatchAt(bat, siriusInputTargetBytes, siriusInputWindowBytes)
}

func splitSiriusBatchAt(
	bat *batch.Batch,
	targetBytes, windowBytes uint64,
) ([]siriusBatchRange, error) {
	return splitSiriusBatchContext(context.Background(), bat, targetBytes, windowBytes)
}

func splitSiriusBatchContext(
	ctx context.Context,
	bat *batch.Batch,
	targetBytes, windowBytes uint64,
) ([]siriusBatchRange, error) {
	if bat == nil || targetBytes == 0 || windowBytes < targetBytes {
		return nil, moerr.NewInvalidInputNoCtx("invalid Sirius input capacity")
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	rows := bat.RowCount()
	if rows == 0 {
		return nil, nil
	}
	var constantBytes uint64
	flatColumns := 0
	varlen := make([][]types.Varlena, len(bat.Vecs))
	for i, vec := range bat.Vecs {
		if vec == nil || !vec.CoversLogicalRows(0, rows) {
			return nil, moerr.NewInvalidInputNoCtx("invalid Sirius input vector length")
		}
		if vec.GetType().TypeSize() <= 0 {
			return nil, moerr.NewInvalidInputNoCtx("invalid Sirius input vector type")
		}
		if vec.IsConstNull() {
			continue
		}
		if vec.IsConst() {
			constantBytes += uint64(len(vec.GetData()))
			if vec.GetType().IsVarlen() {
				descriptors, _ := vector.MustVarlenaRawData(vec)
				if len(descriptors) != 0 && !descriptors[0].IsSmall() {
					_, size := descriptors[0].OffsetLen()
					constantBytes += uint64(size)
				}
			} else {
				constantBytes += uint64(len(vec.GetArea()))
			}
			continue
		}
		flatColumns++
		if vec.GetType().IsVarlen() {
			varlen[i], _ = vector.MustVarlenaRawData(vec)
		}
	}
	if constantBytes > windowBytes {
		return nil, moerr.NewInvalidInputNoCtx("Sirius input row exceeds native window")
	}

	result := make([]siriusBatchRange, 0, 1)
	start := 0
	used := constantBytes
	for row := 0; row < rows; row++ {
		if row&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, context.Cause(ctx)
			}
		}
		rowBytes := uint64(0)
		for i, vec := range bat.Vecs {
			if vec.IsConst() {
				continue
			}
			rowBytes += uint64(vec.GetType().TypeSize())
			if len(varlen[i]) != 0 && !vec.IsNull(uint64(row)) && !varlen[i][row].IsSmall() {
				_, size := varlen[i][row].OffsetLen()
				rowBytes += uint64(size)
			}
		}
		bitmapBytes := uint64(0)
		if (row-start)%64 == 0 {
			bitmapBytes = uint64(flatColumns * 8)
		}
		if rowBytes > windowBytes || bitmapBytes > windowBytes-rowBytes ||
			constantBytes > windowBytes-rowBytes-bitmapBytes {
			return nil, moerr.NewInvalidInputNoCtx("Sirius input row exceeds native window")
		}
		additional := rowBytes + bitmapBytes
		if row > start && (additional > targetBytes || used > targetBytes-additional) {
			result = append(result, siriusBatchRange{start: start, end: row})
			start = row
			used = constantBytes
			bitmapBytes = uint64(flatColumns * 8)
		}
		used += rowBytes + bitmapBytes
		if used > windowBytes {
			return nil, moerr.NewInvalidInputNoCtx("Sirius input range exceeds native window")
		}
	}
	result = append(result, siriusBatchRange{start: start, end: rows})
	var directBytes uint64
	directOversized := false
	for _, vec := range bat.Vecs {
		if vec.IsConstNull() {
			continue
		}
		physical := uint64(len(vec.GetData())) + uint64(len(vec.GetArea()))
		if !vec.IsConst() {
			physical += uint64(((rows + 63) / 64) * 8)
		}
		if physical > targetBytes || directBytes > targetBytes-physical {
			directOversized = true
			break
		}
		directBytes += physical
	}
	if directOversized {
		for i := range result {
			result[i].compact = true
		}
	}
	return result, nil
}

func encodeSiriusBatchRange(
	bat *batch.Batch,
	start, end int,
	compact bool,
	mp *mpool.MPool,
) ([]SiriusInputVector, func(), error) {
	if start < 0 || end <= start || end > bat.RowCount() {
		return nil, func() {}, moerr.NewInvalidInputNoCtx("invalid Sirius input row range")
	}
	whole := start == 0 && end == bat.RowCount()
	result := make([]SiriusInputVector, len(bat.Vecs))
	clones := make([]*vector.Vector, 0, len(bat.Vecs))
	release := func() {
		for _, clone := range clones {
			clone.Free(mp)
		}
	}
	for i, source := range bat.Vecs {
		vec := source
		if !source.IsConstNull() && (!whole || compact) && source.GetType().IsVarlen() {
			var err error
			cloneStart, cloneEnd := start, end
			if source.IsConst() {
				cloneStart, cloneEnd = 0, 1
			}
			vec, err = source.CloneWindow(cloneStart, cloneEnd, mp)
			if err != nil {
				release()
				return nil, func() {}, err
			}
			clones = append(clones, vec)
		}
		encoded := &result[i]
		switch {
		case vec.IsConstNull():
			encoded.Class = SiriusVectorConstantNull
		case vec.IsConst():
			encoded.Class = SiriusVectorConstant
			encoded.Data = vec.GetData()
			encoded.Area = vec.GetArea()
		default:
			encoded.Class = SiriusVectorFlat
			if vec == source {
				size := source.GetType().TypeSize()
				encoded.Data = source.GetData()[start*size : end*size]
			} else {
				encoded.Data = vec.GetData()
			}
			encoded.Area = vec.GetArea()
			encoded.Nulls = siriusNullBits(source, start, end)
		}
	}
	var size uint64
	for _, vec := range result {
		for _, data := range [][]byte{vec.Data, vec.Area, vec.Nulls} {
			if uint64(len(data)) > siriusInputWindowBytes-size {
				release()
				return nil, func() {}, moerr.NewInvalidInputNoCtx("Sirius input range exceeds native window")
			}
			size += uint64(len(data))
		}
	}
	return result, release, nil
}

func siriusNullBits(vec *vector.Vector, start, end int) []byte {
	bits := make([]byte, ((end-start+63)/64)*8)
	vec.GetNulls().Foreach(func(row uint64) bool {
		if row < uint64(start) {
			return true
		}
		if row >= uint64(end) {
			return false
		}
		local := row - uint64(start)
		offset := (local / 64) * 8
		word := binary.LittleEndian.Uint64(bits[offset : offset+8])
		binary.LittleEndian.PutUint64(bits[offset:offset+8], word|uint64(1)<<(local%64))
		return true
	})
	return bits
}
