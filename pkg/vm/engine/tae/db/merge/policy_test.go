// Copyright 2024 Matrix Origin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merge

import (
	"context"
	"math"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/matrixorigin/matrixone/pkg/common/mpool"
	"github.com/matrixorigin/matrixone/pkg/container/batch"
	"github.com/matrixorigin/matrixone/pkg/container/types"
	"github.com/matrixorigin/matrixone/pkg/container/vector"
	"github.com/matrixorigin/matrixone/pkg/fileservice"
	"github.com/matrixorigin/matrixone/pkg/objectio"
	"github.com/matrixorigin/matrixone/pkg/objectio/ioutil"
	"github.com/matrixorigin/matrixone/pkg/pb/api"
	"github.com/matrixorigin/matrixone/pkg/testutil"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/catalog"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/common"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/iface/txnif"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/index"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/options"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/txn/txnbase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig(objectMinOSize uint32, maxOneRun int) *BasicPolicyConfig {
	return &BasicPolicyConfig{
		ObjectMinOsize: objectMinOSize,
		MergeMaxOneRun: maxOneRun,
	}
}

func newSortedDataEntryWithTableEntry(t *testing.T, tbl *catalog.TableEntry, txn txnif.AsyncTxn, v1, v2 int32, size uint32) *catalog.ObjectEntry {
	zm := index.NewZM(types.T_int32, 0)
	index.UpdateZM(zm, types.EncodeInt32(&v1))
	index.UpdateZM(zm, types.EncodeInt32(&v2))
	nobjid := objectio.NewObjectid()
	stats := objectio.NewObjectStatsWithObjectID(&nobjid, false, true, false)
	require.NoError(t, objectio.SetObjectStatsSortKeyZoneMap(stats, zm))
	require.NoError(t, objectio.SetObjectStatsOriginSize(stats, size))
	require.NoError(t, objectio.SetObjectStatsRowCnt(stats, 2))
	entry, err := tbl.CreateObject(txn, &objectio.CreateObjOpt{
		Stats: stats,
	}, nil)
	require.NoError(t, err)
	return entry
}

func newSortedTombstoneEntryWithTableEntry(t *testing.T, tbl *catalog.TableEntry, txn txnif.AsyncTxn, v1, v2 types.Rowid) *catalog.ObjectEntry {
	zm := index.NewZM(types.T_Rowid, 0)
	index.UpdateZM(zm, v1[:])
	index.UpdateZM(zm, v2[:])
	stats := objectio.NewObjectStats()
	require.NoError(t, objectio.SetObjectStatsLocation(stats, objectio.NewRandomLocation(2, 1111)))
	require.NoError(t, objectio.SetObjectStatsSortKeyZoneMap(stats, zm))
	require.NoError(t, objectio.SetObjectStatsRowCnt(stats, 2))
	entry := catalog.NewObjectEntry(tbl, txn, *stats, nil, true)
	entry.GetLastMVCCNode().Txn = nil
	tbl.AddEntryLocked(entry)
	return entry
}

func newSortedTestObjectEntry(t testing.TB, v1, v2 int32, size uint32) *catalog.ObjectEntry {
	zm := index.NewZM(types.T_int32, 0)
	index.UpdateZM(zm, types.EncodeInt32(&v1))
	index.UpdateZM(zm, types.EncodeInt32(&v2))
	stats := objectio.NewObjectStats()
	nobjid := objectio.NewObjectid()
	objName := objectio.BuildObjectNameWithObjectID(&nobjid)
	require.NoError(t, objectio.SetObjectStatsObjectName(stats, objName))
	require.NoError(t, objectio.SetObjectStatsSortKeyZoneMap(stats, zm))
	require.NoError(t, objectio.SetObjectStatsOriginSize(stats, size))
	require.NoError(t, objectio.SetObjectStatsRowCnt(stats, 2))
	return &catalog.ObjectEntry{
		ObjectMVCCNode: catalog.ObjectMVCCNode{ObjectStats: *stats},
	}
}

func newTestVarcharObjectEntry(t testing.TB, v1, v2 string, size uint32) *catalog.ObjectEntry {
	zm := index.NewZM(types.T_varchar, 0)
	index.UpdateZM(zm, []byte(v1))
	index.UpdateZM(zm, []byte(v2))
	stats := objectio.NewObjectStats()
	nobjid := objectio.NewObjectid()
	objName := objectio.BuildObjectNameWithObjectID(&nobjid)
	require.NoError(t, objectio.SetObjectStatsObjectName(stats, objName))
	require.NoError(t, objectio.SetObjectStatsSortKeyZoneMap(stats, zm))
	require.NoError(t, objectio.SetObjectStatsOriginSize(stats, size))
	require.NoError(t, objectio.SetObjectStatsRowCnt(stats, 2))
	return &catalog.ObjectEntry{
		ObjectMVCCNode: catalog.ObjectMVCCNode{ObjectStats: *stats},
	}
}

func newTestObjectEntry(t *testing.T, size uint32, isTombstone bool) *catalog.ObjectEntry {
	stats := objectio.NewObjectStats()
	objid := objectio.NewObjectid()
	objName := objectio.BuildObjectNameWithObjectID(&objid)
	require.NoError(t, objectio.SetObjectStatsObjectName(stats, objName))
	require.NoError(t, objectio.SetObjectStatsOriginSize(stats, size))
	require.NoError(t, objectio.SetObjectStatsRowCnt(stats, 2))

	return &catalog.ObjectEntry{
		ObjectMVCCNode: catalog.ObjectMVCCNode{ObjectStats: *stats},
		ObjectNode:     catalog.ObjectNode{IsTombstone: isTombstone},
	}
}

func TestPolicyTombstone(t *testing.T) {
	common.IsStandaloneBoost.Store(true)
	p := newTombstonePolicy()
	rc := new(resourceController)

	// tombstone policy do not schedule data objects
	p.resetForTable(catalog.MockStaloneTableEntry(0, &catalog.Schema{Extra: &api.SchemaExtra{BlockMaxRows: options.DefaultBlockMaxRows}}), testConfig(100, 2))
	require.False(t, p.onObject(newTestObjectEntry(t, 10, false)))
	require.False(t, p.onObject(newTestObjectEntry(t, 20, false)))
	result := p.revise(rc)
	require.Equal(t, 0, len(result))

	p.resetForTable(catalog.MockStaloneTableEntry(0, &catalog.Schema{Extra: &api.SchemaExtra{BlockMaxRows: options.DefaultBlockMaxRows}}), testConfig(100, 2))
	require.True(t, p.onObject(newTestObjectEntry(t, 10, true)))
	require.True(t, p.onObject(newTestObjectEntry(t, 20, true)))
	result = p.revise(rc)
	require.Equal(t, 1, len(result))
	require.Equal(t, 2, len(result[0].objs))
	require.Equal(t, taskHostDN, result[0].kind)

	// only schedule objects less than cfg.maxOneRun
	p.resetForTable(catalog.MockStaloneTableEntry(0, &catalog.Schema{Extra: &api.SchemaExtra{BlockMaxRows: options.DefaultBlockMaxRows}}), testConfig(100, 2))
	require.True(t, p.onObject(newTestObjectEntry(t, 10, true)))
	require.True(t, p.onObject(newTestObjectEntry(t, 20, true)))
	require.False(t, p.onObject(newTestObjectEntry(t, 30, true)))
	result = p.revise(rc)
	require.Equal(t, 1, len(result))
	require.Equal(t, 2, len(result[0].objs))
	require.Equal(t, taskHostDN, result[0].kind)

	// tombstone do not consider size limit
	p.resetForTable(catalog.MockStaloneTableEntry(0, &catalog.Schema{Extra: &api.SchemaExtra{BlockMaxRows: options.DefaultBlockMaxRows}}), testConfig(100, 3))
	require.True(t, p.onObject(newTestObjectEntry(t, 10, true)))
	require.True(t, p.onObject(newTestObjectEntry(t, 20, true)))
	require.True(t, p.onObject(newTestObjectEntry(t, 120, true)))
	result = p.revise(rc)
	require.Equal(t, 1, len(result))
	require.Equal(t, 3, len(result[0].objs))
	require.Equal(t, taskHostDN, result[0].kind)
}

func TestPolicyGroup(t *testing.T) {
	common.IsStandaloneBoost.Store(true)
	g := newPolicyGroup(newTombstonePolicy())
	g.resetForTable(catalog.MockStaloneTableEntry(0, &catalog.Schema{Extra: &api.SchemaExtra{MaxObjOnerun: 2, BlockMaxRows: options.DefaultBlockMaxRows}}))
	rc := new(resourceController)

	g.onObject(newTestObjectEntry(t, 10, false))
	g.onObject(newTestObjectEntry(t, 20, false))
	g.onObject(newTestObjectEntry(t, 30, false))
	g.onObject(newTestObjectEntry(t, 10, true))
	g.onObject(newTestObjectEntry(t, 20, true))
	g.onObject(newTestObjectEntry(t, 30, true))

	results := g.revise(rc)
	require.Equal(t, 1, len(results))
	require.Equal(t, taskHostDN, results[0].kind)

	require.Equal(t, 2, len(results[0].objs))
}

const overlapSizeThreshold = common.DefaultMinOsizeQualifiedMB * common.Const1MBytes

func TestObjOverlap(t *testing.T) {

	// empty policy
	policy := newObjOverlapPolicy()
	rc := new(resourceController)
	rc.setMemLimit(estimateMemUsagePerRow * 20)
	objs := policy.revise(rc)
	for _, obj := range objs {
		require.Equal(t, 0, len(obj.objs))
	}

	policy.resetForTable(nil, defaultBasicConfig)

	// no overlap
	entry1 := newSortedTestObjectEntry(t, 1, 2, overlapSizeThreshold)
	entry2 := newSortedTestObjectEntry(t, 3, 4, overlapSizeThreshold)
	require.True(t, policy.onObject(entry1))
	require.True(t, policy.onObject(entry2))
	objs = policy.revise(rc)
	for _, obj := range objs {
		require.Equal(t, 0, len(obj.objs))
	}

	policy.resetForTable(nil, defaultBasicConfig)

	// overlap
	entry3 := newSortedTestObjectEntry(t, 1, 4, overlapSizeThreshold)
	entry4 := newSortedTestObjectEntry(t, 2, 3, overlapSizeThreshold)
	require.True(t, policy.onObject(entry3))
	require.True(t, policy.onObject(entry4))
	objs = policy.revise(rc)
	require.Equal(t, 0, len(objs))
	policy.resetForTable(nil, defaultBasicConfig)

	// entry is not sorted
	entry5 := newTestObjectEntry(t, overlapSizeThreshold, false)
	entry6 := newTestObjectEntry(t, overlapSizeThreshold, false)
	policy.onObject(entry5)
	policy.onObject(entry6)
	require.Equal(t, 6, len(policy.leveledObjects))
	objs = policy.revise(rc)
	for _, obj := range objs {
		require.Equal(t, 0, len(obj.objs))
	}

	policy.resetForTable(nil, defaultBasicConfig)

	// two overlap set:
	// {entry7, entry8}
	// {entry9, entry10, entry11}
	entry7 := newSortedTestObjectEntry(t, 1, 4, overlapSizeThreshold)
	entry8 := newSortedTestObjectEntry(t, 2, 3, overlapSizeThreshold)

	entry9 := newSortedTestObjectEntry(t, 11, 14, overlapSizeThreshold)
	entry10 := newSortedTestObjectEntry(t, 12, 13, overlapSizeThreshold)
	entry11 := newSortedTestObjectEntry(t, 13, 15, overlapSizeThreshold)

	require.True(t, policy.onObject(entry7))
	require.True(t, policy.onObject(entry8))
	require.True(t, policy.onObject(entry9))
	require.True(t, policy.onObject(entry10))
	require.True(t, policy.onObject(entry11))

	objs = policy.revise(rc)
	require.Equal(t, 0, len(objs))

	policy.resetForTable(nil, defaultBasicConfig)

	// no enough memory
	entry12 := newSortedTestObjectEntry(t, 1, 4, overlapSizeThreshold)
	entry13 := newSortedTestObjectEntry(t, 2, 3, overlapSizeThreshold)

	require.True(t, policy.onObject(entry12))
	require.True(t, policy.onObject(entry13))

	objs = policy.revise(rc)
	for _, obj := range objs {
		require.Equal(t, 2, len(obj.objs))
	}

	policy.resetForTable(nil, defaultBasicConfig)

	for i := range 30 {
		require.True(t, policy.onObject(newSortedTestObjectEntry(t, int32(i), int32(i+100), 1)))
	}
	rc.setMemLimit(math.MaxInt64)
	objs = policy.revise(rc)
	require.Equal(t, 1, len(objs))
	require.Equal(t, 30, len(objs[0].objs))

	policy.resetForTable(nil, defaultBasicConfig)
}

func TestPolicyCompact(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("memory", fileservice.DisabledCacheConfig, nil)
	require.NoError(t, err)
	p := newObjCompactPolicy(fs)
	rc := new(resourceController)

	cata := catalog.MockCatalog(nil)
	defer cata.Close()
	txnMgr := txnbase.NewTxnManager(catalog.MockTxnStoreFactory(cata), catalog.MockTxnFactory(cata), types.NewMockHLCClock(1))
	txnMgr.Start(context.Background())
	defer txnMgr.Stop()
	txn1, _ := txnMgr.StartTxn(nil)
	db, err := cata.CreateDBEntry("db", "", "", txn1)
	require.NoError(t, err)
	catalog.MockSchema(1, 0)
	tbl, err := db.CreateTableEntry(catalog.MockSchema(1, 0), txn1, nil)
	require.NoError(t, err)
	require.NoError(t, txn1.Commit(context.Background()))
	obj := catalog.MockObjEntryWithTbl(tbl, math.MaxUint32, false)
	tombstone := catalog.MockObjEntryWithTbl(tbl, math.MaxUint32, true)
	require.NoError(t, objectio.SetObjectStatsOriginSize(tombstone.GetObjectStats(), math.MaxUint32))
	tbl.AddEntryLocked(obj)
	tbl.AddEntryLocked(tombstone)
	p.resetForTable(tbl, &BasicPolicyConfig{})
	p.onObject(obj)

	objs := p.revise(rc)
	require.Equal(t, 0, len(objs))

	txn2, _ := txnMgr.StartTxn(nil)
	entry1 := newSortedDataEntryWithTableEntry(t, tbl, txn2, 0, 1, overlapSizeThreshold)
	require.NoError(t, txn2.Commit(context.Background()))
	require.False(t, p.onObject(entry1))

	txn3, _ := txnMgr.StartTxn(nil)
	newSortedTombstoneEntryWithTableEntry(t, tbl, txn3, types.Rowid{0}, types.Rowid{1})
	require.NoError(t, txn3.Commit(context.Background()))
	require.False(t, p.onObject(entry1))
}

func Test_timeout(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("memory", fileservice.DisabledCacheConfig, nil)
	require.NoError(t, err)
	p := newObjCompactPolicy(fs)

	cata := catalog.MockCatalog(nil)
	defer cata.Close()
	txnMgr := txnbase.NewTxnManager(catalog.MockTxnStoreFactory(cata), catalog.MockTxnFactory(cata), types.NewMockHLCClock(1))
	txnMgr.Start(context.Background())
	defer txnMgr.Stop()
	txn1, _ := txnMgr.StartTxn(nil)
	db, err := cata.CreateDBEntry("db", "", "", txn1)
	require.NoError(t, err)
	catalog.MockSchema(1, 0)
	tbl, err := db.CreateTableEntry(catalog.MockSchema(1, 0), txn1, nil)
	require.NoError(t, err)
	require.NoError(t, txn1.Commit(context.Background()))

	p.resetForTable(tbl, defaultBasicConfig)

	txn3, _ := txnMgr.StartTxn(nil)
	ent3 := newSortedTombstoneEntryWithTableEntry(t, tbl, txn3, types.Rowid{0}, types.Rowid{1})
	ent3.IsTombstone = false
	originSizes := ent3.ObjectStats[149 : 149+4]
	minSizeBytes := types.EncodeUint32(&defaultBasicConfig.ObjectMinOsize)
	copy(originSizes, minSizeBytes)

	require.NoError(t, txn3.Commit(context.Background()))
	require.False(t, p.onObject(ent3))
}

func TestSegLevel(t *testing.T) {
	require.Equal(t, 0, segLevel(1))
	require.Equal(t, 1, segLevel(2))
	require.Equal(t, 1, segLevel(3))
	require.Equal(t, 2, segLevel(4))
	require.Equal(t, 2, segLevel(5))
	require.Equal(t, 2, segLevel(6))
	require.Equal(t, 2, segLevel(14))
	require.Equal(t, 2, segLevel(15))
	require.Equal(t, 3, segLevel(16))
	require.Equal(t, 3, segLevel(17))
	require.Equal(t, 3, segLevel(63))
	require.Equal(t, 4, segLevel(64))
	require.Equal(t, 4, segLevel(65))
	require.Equal(t, 4, segLevel(255))
	require.Equal(t, 5, segLevel(256))
	require.Equal(t, 5, segLevel(257))
}

func TestCheckTombstone(t *testing.T) {
	mp := mpool.MustNewZero()

	fs := testutil.NewSharedFS()

	rowCnt := 100
	ssCnt := 2

	rowids := make([]types.Rowid, rowCnt)
	metas := make([]objectio.ObjectDataMeta, ssCnt)
	for i := 0; i < ssCnt; i++ {
		writer := ioutil.ConstructTombstoneWriter(objectio.HiddenColumnSelection_None, fs)
		assert.NotNil(t, writer)

		bat := batch.NewWithSize(2)
		bat.Vecs[0] = vector.NewVec(types.T_Rowid.ToType())
		bat.Vecs[1] = vector.NewVec(types.T_int32.ToType())

		for j := 0; j < rowCnt; j++ {
			row := types.RandomRowid()
			rowids[j] = row
			pk := rand.Int()

			err := vector.AppendFixed[types.Rowid](bat.Vecs[0], row, false, mp)
			require.NoError(t, err)

			err = vector.AppendFixed[int32](bat.Vecs[1], int32(pk), false, mp)
			require.NoError(t, err)
		}

		_, err := writer.WriteBatch(bat)
		require.NoError(t, err)

		_, _, err = writer.Sync(context.Background())
		require.NoError(t, err)

		ss := writer.GetObjectStats()
		require.Equal(t, rowCnt, int(ss.Rows()))
		meta, err := loadTombstoneMeta(&ss, fs)
		require.NoError(t, err)
		metas[i] = meta
	}
	for _, rowID := range rowids {
		id := rowID.BorrowObjectID()
		for i := range metas {
			ok := checkTombstoneMeta(metas[i], id)
			if i == 0 {
				require.False(t, ok)
			} else {
				require.True(t, ok)
			}
		}
	}
}

func TestObjectsWithMaximumOverlaps(t *testing.T) {
	o1 := newSortedTestObjectEntry(t, 0, 50, math.MaxInt32)
	o2 := newSortedTestObjectEntry(t, 51, 100, math.MaxInt32)
	o3 := newSortedTestObjectEntry(t, 49, 52, math.MaxInt32)
	o4 := newSortedTestObjectEntry(t, 1, 52, math.MaxInt32)
	o5 := newSortedTestObjectEntry(t, 50, 51, math.MaxInt32)
	o6 := newSortedTestObjectEntry(t, 55, 60, math.MaxInt32)

	res1 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o2}), 2)
	require.Equal(t, 0, len(res1))

	res2 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o3}), 2)
	require.Equal(t, 1, len(res2))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o1, o3}, res2[0])

	res3 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o2, o3}), 2)
	require.Equal(t, 1, len(res3))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o2, o3}, res3[0])

	res4 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o2, o3}), 2)
	require.Equal(t, 1, len(res4))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o1, o3}, res4[0])

	res5 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o2, o3}), 2)
	require.Equal(t, 1, len(res5))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o1, o3}, res5[0])

	res6 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o2, o3, o4}), 2)
	require.Equal(t, 1, len(res6))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o1, o3, o4}, res6[0])

	res7 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o5}), 2)
	require.Equal(t, 1, len(res7))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o1, o5}, res7[0])

	res8 := objectsWithGivenOverlaps(makeEndPoints([]*catalog.ObjectEntry{o1, o2, o3, o4, o5, o6}), 2)
	require.Equal(t, 2, len(res8))
	require.ElementsMatch(t, []*catalog.ObjectEntry{o1, o3, o4, o5}, res8[0])
	require.ElementsMatch(t, []*catalog.ObjectEntry{o2, o6}, res8[1])
}

func TestLargeMerge(t *testing.T) {
	{
		objs := make([]*catalog.ObjectEntry, 500000)
		for i := range objs {
			objs[i] = newTestVarcharObjectEntry(t, "a", "a", 110*common.Const1MBytes)
		}

		policy := newObjOverlapPolicy()
		policy.resetForTable(nil, defaultBasicConfig)

		rc := new(resourceController)
		rc.setMemLimit(50 * common.Const1GBytes)
		for _, obj := range objs {
			policy.onObject(obj)
		}
		results := policy.revise(rc)
		// skip all objs with min = max
		require.Equal(t, 0, len(results))
	}

	{
		objs := make([]*catalog.ObjectEntry, 500000)
		for i := range objs {
			objs[i] = newTestVarcharObjectEntry(t, "a", "zdff", 110*common.Const1MBytes)
		}

		policy := newObjOverlapPolicy()
		policy.resetForTable(nil, defaultBasicConfig)

		rc := new(resourceController)
		rc.setMemLimit(50 * common.Const1GBytes)
		for _, obj := range objs {
			policy.onObject(obj)
		}
		results := policy.revise(rc)
		require.Equal(t, 1, len(results))
		// mem control squeeze out some objs
		require.Less(t, len(results[0].objs), 500000)
	}
}

func TestVarcharOverflow(t *testing.T) {
	objs := make([]*catalog.ObjectEntry, 10)
	for i := range objs {
		objs[i] = newTestVarcharObjectEntry(t, strings.Repeat("a", 100), strings.Repeat("a", 100), 110*common.Const1MBytes)
	}
	policy := newObjOverlapPolicy()
	policy.resetForTable(nil, defaultBasicConfig)
	rc := new(resourceController)
	rc.setMemLimit(50 * common.Const1GBytes)

	for _, obj := range objs {
		policy.onObject(obj)
	}
	results := policy.revise(rc)
	require.Equal(t, 0, len(results))
}

func TestEmptyZm(t *testing.T) {
	objs := make([]*catalog.ObjectEntry, 300)
	for i := range objs {
		objs[i] = newTestObjectEntry(t, 1*common.Const1MBytes, false)
	}

	policy := newObjOverlapPolicy()
	policy.resetForTable(nil, defaultBasicConfig)

	rc := new(resourceController)
	rc.setMemLimit(50 * common.Const1MBytes)
	for _, obj := range objs {
		policy.onObject(obj)
	}
	results := policy.revise(rc)
	require.Equal(t, 1, len(results))
	t.Log(len(results[0].objs))
}

func TestToolFunctions(t *testing.T) {
	objs := make([]*catalog.ObjectEntry, 101)
	for i := range objs {
		objs[i] = newTestObjectEntry(t, 1*common.Const1MBytes, false)
	}

	require.True(t, hasHundredSmallObjs(objs, 2*common.Const1MBytes))

	// test for IsSameSegment
	segID := objectio.NewSegmentid()
	objectio.SetObjectStatsObjectName(&objs[0].ObjectStats, objectio.BuildObjectName(segID, 1))
	objectio.SetObjectStatsObjectName(&objs[1].ObjectStats, objectio.BuildObjectName(segID, 2))
	objectio.SetObjectStatsObjectName(&objs[2].ObjectStats, objectio.BuildObjectName(segID, 3))
	require.True(t, IsSameSegment(objs[:3]))
	require.False(t, IsSameSegment(objs[:4]))

	require.False(t, isAllGreater(objs, 2*common.Const1MBytes))
	require.True(t, isAllGreater(objs, common.Const1MBytes/2))
}
