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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matrixorigin/matrixone/pkg/fileservice"
	"github.com/stretchr/testify/require"
)

type resolveAuditFailureFS struct {
	fileservice.FileService
	writeErr  error
	deleteErr error
	listErr   error
}

type resolveAuditCountingFS struct {
	fileservice.FileService
	listCalls atomic.Int64
}

func (f *resolveAuditCountingFS) List(
	ctx context.Context,
	dir string,
) iter.Seq2[*fileservice.DirEntry, error] {
	f.listCalls.Add(1)
	return f.FileService.List(ctx, dir)
}

func (f resolveAuditFailureFS) Write(ctx context.Context, vector fileservice.IOVector) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	return f.FileService.Write(ctx, vector)
}

func (f resolveAuditFailureFS) Delete(ctx context.Context, names ...string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.FileService.Delete(ctx, names...)
}

func (f resolveAuditFailureFS) List(
	ctx context.Context,
	dir string,
) iter.Seq2[*fileservice.DirEntry, error] {
	if f.listErr == nil {
		return f.FileService.List(ctx, dir)
	}
	return func(yield func(*fileservice.DirEntry, error) bool) {
		yield(nil, f.listErr)
	}
}

type resolveAuditZeroReader struct{}

func (resolveAuditZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type resolveAuditPanicReader struct{}

func (resolveAuditPanicReader) Read([]byte) (int, error) { panic("audit random panic") }

type resolveAuditSequenceReader struct {
	mu   sync.Mutex
	next uint64
}

func (r *resolveAuditSequenceReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(p)
	r.next++
	binary.BigEndian.PutUint64(p[len(p)-8:], r.next)
	return len(p), nil
}

func TestFileServiceResolveAuditRecorderPersistsRedactedWriteOnceRecord(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("resolve-audit", fileservice.CacheConfig{}, nil)
	require.NoError(t, err)
	value, err := NewFileServiceResolveAuditRecorder(fs, "cn/private/path")
	require.NoError(t, err)
	recorder := value.(*fileServiceResolveAuditRecorder)
	recorder.now = func() time.Time { return time.Unix(7, 8).UTC() }
	recorder.random = resolveAuditZeroReader{}

	queryID := []byte("super-secret-query-id")
	clientHash := bytes.Repeat([]byte{0x2a}, sha256.Size)
	readHash := bytes.Repeat([]byte{0x3b}, sha256.Size)
	event := ResolveAuditEvent{
		AccountID: 1, DatabaseID: 2, TableID: 3, QueryID: queryID,
		ClientSPKIHash: clientHash, ReadRefSHA256: readHash,
	}
	require.NoError(t, recorder.RecordResolve(t.Context(), event))

	files := listResolveAuditFiles(t, fs, recorder)
	require.Len(t, files, 1)
	require.NotContains(t, files[0], "cn/private/path")
	payload := readResolveAuditFile(t, fs, files[0])
	require.NotContains(t, string(payload), string(queryID))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Len(t, decoded, 7)
	queryHash := sha256.Sum256(queryID)
	require.Equal(t, hex.EncodeToString(queryHash[:]), decoded["query_id_sha256"])
	require.Equal(t, hex.EncodeToString(clientHash), decoded["client_spki_sha256"])
	require.Equal(t, hex.EncodeToString(readHash), decoded["read_ref_sha256"])

	err = recorder.RecordResolve(t.Context(), event)
	require.ErrorContains(t, err, "identity collision",
		"same timestamp and random identity must fail without replacing its immutable record")
	require.Equal(t, files, listResolveAuditFiles(t, fs, recorder))
	require.Equal(t, 64<<20, maxResolveAuditRetainedPayloadBytes)
}

func TestFileServiceResolveAuditRecorderBoundsAndRollsPartitions(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("resolve-audit-retention", fileservice.CacheConfig{}, nil)
	require.NoError(t, err)
	recorder := newTestResolveAuditRecorder(t, fs, "cn-retention", 2, 2)
	recorder.now = func() time.Time { return time.Unix(9, 10).UTC() }
	recorder.random = new(resolveAuditSequenceReader)

	for i := 0; i < 5; i++ {
		require.NoError(t, recorder.RecordResolve(t.Context(), resolveAuditEvent(byte(i))))
		objects, payloadBytes := resolveAuditUsage(t, fs, recorder)
		require.LessOrEqual(t, objects, 4)
		require.LessOrEqual(t, payloadBytes, int64(4*maxResolveAuditRecordSize))
	}

	partitions := listResolveAuditPartitions(t, fs, recorder)
	require.Equal(t, []string{
		formatResolveAuditPartition(2),
		formatResolveAuditPartition(3),
	}, partitions)
	files := listResolveAuditFiles(t, fs, recorder)
	require.Len(t, files, 3, "rollover removes the complete oldest partition before admission")

	wantHashes := make([]string, 0, 3)
	for i := 2; i < 5; i++ {
		digest := sha256.Sum256([]byte{byte(i)})
		wantHashes = append(wantHashes, hex.EncodeToString(digest[:]))
	}
	gotHashes := make([]string, 0, len(files))
	for _, name := range files {
		var record resolveAuditRecord
		require.NoError(t, json.Unmarshal(readResolveAuditFile(t, fs, name), &record))
		gotHashes = append(gotHashes, record.QueryIDSHA256)
	}
	sort.Strings(wantHashes)
	sort.Strings(gotHashes)
	require.Equal(t, wantHashes, gotHashes)
}

func TestFileServiceResolveAuditRecorderConcurrentWritersAndRestartStayBounded(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("resolve-audit-concurrent", fileservice.CacheConfig{}, nil)
	require.NoError(t, err)
	first := newTestResolveAuditRecorder(t, fs, "cn-concurrent", 3, 2)
	second := newTestResolveAuditRecorder(t, fs, "cn-concurrent", 3, 2)
	sequence := new(resolveAuditSequenceReader)
	now := func() time.Time { return time.Unix(11, 12).UTC() }
	for _, recorder := range []*fileServiceResolveAuditRecorder{first, second} {
		recorder.now = now
		recorder.random = sequence
	}

	const writers = 12
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			recorder := first
			if i%2 != 0 {
				recorder = second
			}
			errs <- recorder.RecordResolve(t.Context(), resolveAuditEvent(byte(i)))
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for writeErr := range errs {
		require.NoError(t, writeErr)
	}
	require.Len(t, listResolveAuditFiles(t, fs, first), 6)
	require.Len(t, listResolveAuditPartitions(t, fs, first), 2)

	// A fresh recorder has no process-local partition cursor. It reconstructs
	// the durable generations and continues the same bound after restart.
	restarted := newTestResolveAuditRecorder(t, fs, "cn-concurrent", 3, 2)
	restarted.states = new(resolveAuditStateCache)
	restarted.now = now
	restarted.random = sequence
	for i := writers; i < writers+3; i++ {
		require.NoError(t, restarted.RecordResolve(t.Context(), resolveAuditEvent(byte(i))))
	}
	objects, payloadBytes := resolveAuditUsage(t, fs, restarted)
	require.Equal(t, 6, objects)
	require.LessOrEqual(t, payloadBytes, int64(6*maxResolveAuditRecordSize))
	require.Len(t, listResolveAuditPartitions(t, fs, restarted), 2)
}

func TestFileServiceResolveAuditRecorderStateCacheIsBounded(t *testing.T) {
	cache := new(resolveAuditStateCache)
	for i := 0; i < resolveAuditCachedNamespaces+2; i++ {
		state := cache.state(string(rune('a'+i)), 1, 1)
		state.loaded = true
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	require.Len(t, cache.entries, resolveAuditCachedNamespaces)
}

func TestFileServiceResolveAuditRecorderListsOnlyForRecovery(t *testing.T) {
	memory, err := fileservice.NewMemoryFS("resolve-audit-recovery", fileservice.CacheConfig{}, nil)
	require.NoError(t, err)
	fs := &resolveAuditCountingFS{FileService: memory}
	recorder := newTestResolveAuditRecorder(t, fs, "cn-recovery", 3, 2)
	sequence := new(resolveAuditSequenceReader)
	recorder.random = sequence
	require.NoError(t, recorder.RecordResolve(t.Context(), resolveAuditEvent(1)))
	firstRecoveryLists := fs.listCalls.Load()
	require.Positive(t, firstRecoveryLists)
	require.NoError(t, recorder.RecordResolve(t.Context(), resolveAuditEvent(2)))
	require.Equal(t, firstRecoveryLists, fs.listCalls.Load(), "steady-state admission must not relist the journal")

	restarted := newTestResolveAuditRecorder(t, fs, "cn-recovery", 3, 2)
	restarted.states = new(resolveAuditStateCache)
	restarted.random = sequence
	require.NoError(t, restarted.RecordResolve(t.Context(), resolveAuditEvent(3)))
	require.Greater(t, fs.listCalls.Load(), firstRecoveryLists, "restart must reconstruct durable state")
}

func TestFileServiceResolveAuditRecorderFailsClosed(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("resolve-audit-failures", fileservice.CacheConfig{}, nil)
	require.NoError(t, err)
	recorder := newTestResolveAuditRecorder(t, fs, "cn-1", 2, 2)
	recorder.random = new(resolveAuditSequenceReader)
	event := resolveAuditEvent(1)

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, recorder.RecordResolve(canceled, event), context.Canceled)
	require.ErrorContains(t, recorder.RecordResolve(t.Context(), ResolveAuditEvent{}), "invalid resolve audit hashes")

	want := errors.New("audit write failed")
	recorder.fs = resolveAuditFailureFS{FileService: fs, writeErr: want}
	require.ErrorIs(t, recorder.RecordResolve(t.Context(), event), want)
	require.Empty(t, listResolveAuditFiles(t, fs, recorder))

	recorder.fs = resolveAuditFailureFS{FileService: fs, listErr: want}
	require.ErrorIs(t, recorder.RecordResolve(t.Context(), event), want)
	require.Empty(t, listResolveAuditFiles(t, fs, recorder))

	recorder.fs = fs
	recorder.random = io.LimitReader(bytes.NewReader(nil), 0)
	require.ErrorContains(t, recorder.RecordResolve(t.Context(), event), "create resolve audit identity")
	recorder.random = resolveAuditPanicReader{}
	require.ErrorContains(t, recorder.RecordResolve(t.Context(), event), "panicked")
	recorder.random = new(resolveAuditSequenceReader)
	require.NoError(t, recorder.RecordResolve(t.Context(), event), "panic must release admission and permit recovery")

	_, err = NewFileServiceResolveAuditRecorder(nil, "cn-1")
	require.Error(t, err)
	_, err = NewFileServiceResolveAuditRecorder(fs, "")
	require.Error(t, err)
	_, err = newFileServiceResolveAuditRecorder(fs, "cn-1", resolveAuditRetentionPolicy{})
	require.Error(t, err)
}

func TestFileServiceResolveAuditRecorderRolloverFailureDeniesBeforePublication(t *testing.T) {
	fs, err := fileservice.NewMemoryFS("resolve-audit-rollover-failure", fileservice.CacheConfig{}, nil)
	require.NoError(t, err)
	recorder := newTestResolveAuditRecorder(t, fs, "cn-rollover-failure", 1, 1)
	recorder.now = func() time.Time { return time.Unix(13, 14).UTC() }
	recorder.random = new(resolveAuditSequenceReader)
	first := resolveAuditEvent(1)
	second := resolveAuditEvent(2)
	require.NoError(t, recorder.RecordResolve(t.Context(), first))

	want := errors.New("audit delete failed")
	recorder.fs = resolveAuditFailureFS{FileService: fs, deleteErr: want}
	require.ErrorIs(t, recorder.RecordResolve(t.Context(), second), want)
	files := listResolveAuditFiles(t, fs, recorder)
	require.Len(t, files, 1)
	var retained resolveAuditRecord
	require.NoError(t, json.Unmarshal(readResolveAuditFile(t, fs, files[0]), &retained))
	firstHash := sha256.Sum256(first.QueryID)
	require.Equal(t, hex.EncodeToString(firstHash[:]), retained.QueryIDSHA256)

	recorder.fs = fs
	require.NoError(t, recorder.RecordResolve(t.Context(), second))
	files = listResolveAuditFiles(t, fs, recorder)
	require.Len(t, files, 1)
	require.NoError(t, json.Unmarshal(readResolveAuditFile(t, fs, files[0]), &retained))
	secondHash := sha256.Sum256(second.QueryID)
	require.Equal(t, hex.EncodeToString(secondHash[:]), retained.QueryIDSHA256)
}

func newTestResolveAuditRecorder(
	t *testing.T,
	fs fileservice.FileService,
	cnUUID string,
	recordsPerPartition int,
	retainedPartitions int,
) *fileServiceResolveAuditRecorder {
	t.Helper()
	recorder, err := newFileServiceResolveAuditRecorder(fs, cnUUID, resolveAuditRetentionPolicy{
		recordsPerPartition: recordsPerPartition,
		retainedPartitions:  retainedPartitions,
	})
	require.NoError(t, err)
	return recorder
}

func resolveAuditEvent(id byte) ResolveAuditEvent {
	return ResolveAuditEvent{
		AccountID:      uint64(id),
		DatabaseID:     uint64(id) + 1,
		TableID:        uint64(id) + 2,
		QueryID:        []byte{id},
		ClientSPKIHash: bytes.Repeat([]byte{id + 3}, sha256.Size),
		ReadRefSHA256:  bytes.Repeat([]byte{id + 4}, sha256.Size),
	}
}

func listResolveAuditPartitions(
	t *testing.T,
	fs fileservice.FileService,
	recorder *fileServiceResolveAuditRecorder,
) []string {
	t.Helper()
	partitions := make([]string, 0, recorder.retainedPartitions)
	for entry, err := range fs.List(t.Context(), recorder.partitionsPrefix()) {
		require.NoError(t, err)
		require.NotNil(t, entry)
		require.True(t, entry.IsDir)
		partitions = append(partitions, entry.Name)
	}
	sort.Strings(partitions)
	return partitions
}

func listResolveAuditFiles(
	t *testing.T,
	fs fileservice.FileService,
	recorder *fileServiceResolveAuditRecorder,
) []string {
	t.Helper()
	files := make([]string, 0, recorder.recordsPerPartition*recorder.retainedPartitions)
	for _, partition := range listResolveAuditPartitions(t, fs, recorder) {
		dir := path.Join(recorder.partitionsPrefix(), partition)
		for entry, err := range fs.List(t.Context(), dir) {
			require.NoError(t, err)
			require.NotNil(t, entry)
			require.False(t, entry.IsDir)
			files = append(files, path.Join(dir, entry.Name))
		}
	}
	sort.Strings(files)
	return files
}

func resolveAuditUsage(
	t *testing.T,
	fs fileservice.FileService,
	recorder *fileServiceResolveAuditRecorder,
) (objects int, payloadBytes int64) {
	t.Helper()
	for _, partition := range listResolveAuditPartitions(t, fs, recorder) {
		dir := path.Join(recorder.partitionsPrefix(), partition)
		for entry, err := range fs.List(t.Context(), dir) {
			require.NoError(t, err)
			require.NotNil(t, entry)
			require.False(t, entry.IsDir)
			objects++
			payloadBytes += entry.Size
		}
	}
	return objects, payloadBytes
}

func readResolveAuditFile(t *testing.T, fs fileservice.FileService, name string) []byte {
	t.Helper()
	vector := fileservice.IOVector{
		FilePath: name,
		Entries:  []fileservice.IOEntry{{Offset: 0, Size: -1}},
	}
	require.NoError(t, fs.Read(t.Context(), &vector))
	payload := append([]byte(nil), vector.Entries[0].Data...)
	vector.Release()
	return payload
}
