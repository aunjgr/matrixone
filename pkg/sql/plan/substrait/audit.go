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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/fileservice"
)

const (
	resolveAuditVersion                 = 1
	resolveAuditRandomBytes             = 16
	resolveAuditPartitionNameWidth      = 20
	resolveAuditDeleteBatchSize         = 128
	resolveAuditRecordsPerPartition     = 1024
	resolveAuditRetainedPartitions      = 32
	resolveAuditCachedNamespaces        = 4
	maxResolveAuditRecordSize           = 2 << 10
	maxResolveAuditRetainedPayloadBytes = resolveAuditRecordsPerPartition *
		resolveAuditRetainedPartitions * maxResolveAuditRecordSize
)

type fileServiceResolveAuditRecorder struct {
	fs                  fileservice.FileService
	prefix              string
	admissionKey        string
	admission           journalAdmissionCoordinator
	states              *resolveAuditStateCache
	recordsPerPartition int
	retainedPartitions  int
	now                 func() time.Time
	random              io.Reader
}

type resolveAuditRetentionPolicy struct {
	recordsPerPartition int
	retainedPartitions  int
}

type resolveAuditPartition struct {
	generation uint64
	name       string
	records    []string
}

type resolveAuditJournalState struct {
	loaded     bool
	partitions []resolveAuditPartition
	identities map[string]struct{}
}

func (s *resolveAuditJournalState) invalidate() {
	s.loaded = false
	s.partitions = nil
	s.identities = nil
}

type resolveAuditStateCache struct {
	mu      sync.Mutex
	tick    uint64
	entries map[string]*resolveAuditStateCacheEntry
}

type resolveAuditStateCacheEntry struct {
	state               resolveAuditJournalState
	recordsPerPartition int
	retainedPartitions  int
	lastUsed            uint64
}

func (c *resolveAuditStateCache) state(
	key string,
	recordsPerPartition int,
	retainedPartitions int,
) *resolveAuditJournalState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*resolveAuditStateCacheEntry)
	}
	c.tick++
	entry := c.entries[key]
	if entry != nil && (entry.recordsPerPartition != recordsPerPartition ||
		entry.retainedPartitions != retainedPartitions) {
		delete(c.entries, key)
		entry = nil
	}
	if entry == nil {
		if len(c.entries) == resolveAuditCachedNamespaces {
			var oldestKey string
			var oldestTick uint64
			for candidateKey, candidate := range c.entries {
				if oldestKey == "" || candidate.lastUsed < oldestTick {
					oldestKey = candidateKey
					oldestTick = candidate.lastUsed
				}
			}
			delete(c.entries, oldestKey)
		}
		entry = &resolveAuditStateCacheEntry{
			recordsPerPartition: recordsPerPartition,
			retainedPartitions:  retainedPartitions,
		}
		c.entries[key] = entry
	}
	entry.lastUsed = c.tick
	return &entry.state
}

var localProcessResolveAuditAdmission singleProcessJournalAdmission
var localProcessResolveAuditStates resolveAuditStateCache

type resolveAuditRecord struct {
	Version          uint8  `json:"version"`
	AccountID        uint64 `json:"account_id"`
	DatabaseID       uint64 `json:"database_id"`
	TableID          uint64 `json:"table_id"`
	QueryIDSHA256    string `json:"query_id_sha256"`
	ClientSPKISHA256 string `json:"client_spki_sha256"`
	ReadRefSHA256    string `json:"read_ref_sha256"`
}

// NewFileServiceResolveAuditRecorder creates the durable, write-once audit
// owner used by ordinary Flight. The stable CN scope is hashed so the storage
// path does not expose or accept path syntax from a configured service ID.
//
// The journal retains at most resolveAuditRetainedPartitions partitions of at
// most resolveAuditRecordsPerPartition immutable records: 32,768 objects and
// maxResolveAuditRetainedPayloadBytes encoded bytes. Same-namespace writers in
// this process are serialized; restart state comes only from FileService. The
// co-located launcher must continue to prevent overlapping process generations
// for one CN UUID because FileService has no cross-process compare-and-swap.
func NewFileServiceResolveAuditRecorder(
	fs fileservice.FileService,
	cnUUID string,
) (ResolveAuditRecorder, error) {
	return newFileServiceResolveAuditRecorder(fs, cnUUID, resolveAuditRetentionPolicy{
		recordsPerPartition: resolveAuditRecordsPerPartition,
		retainedPartitions:  resolveAuditRetainedPartitions,
	})
}

func newFileServiceResolveAuditRecorder(
	fs fileservice.FileService,
	cnUUID string,
	policy resolveAuditRetentionPolicy,
) (*fileServiceResolveAuditRecorder, error) {
	if fs == nil || cnUUID == "" || policy.recordsPerPartition <= 0 ||
		policy.recordsPerPartition > resolveAuditRecordsPerPartition || policy.retainedPartitions <= 0 ||
		policy.retainedPartitions > resolveAuditRetainedPartitions ||
		policy.recordsPerPartition > int(^uint(0)>>1)/policy.retainedPartitions {
		return nil, moerr.NewBadConfigNoCtx("invalid Sirius resolve audit storage")
	}
	scope := sha256.Sum256([]byte(cnUUID))
	prefix := path.Join("sirius", "resolve-audit", hex.EncodeToString(scope[:]), "v1")
	return &fileServiceResolveAuditRecorder{
		fs:                  fs,
		prefix:              prefix,
		admissionKey:        strings.ToLower(fs.Name()) + ":" + prefix,
		admission:           &localProcessResolveAuditAdmission,
		states:              &localProcessResolveAuditStates,
		recordsPerPartition: policy.recordsPerPartition,
		retainedPartitions:  policy.retainedPartitions,
		now:                 time.Now,
		random:              rand.Reader,
	}, nil
}

func (a *fileServiceResolveAuditRecorder) RecordResolve(
	ctx context.Context,
	event ResolveAuditEvent,
) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = moerr.NewInternalErrorNoCtxf("substrait: persist resolve audit panicked: %v", recovered)
		}
	}()
	if a == nil || a.fs == nil || a.admission == nil || a.states == nil || a.admissionKey == "" ||
		a.recordsPerPartition <= 0 || a.retainedPartitions <= 0 || a.now == nil || a.random == nil {
		return moerr.NewInternalErrorNoCtx("substrait: resolve audit recorder is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if len(event.ClientSPKIHash) != sha256.Size || len(event.ReadRefSHA256) != sha256.Size {
		return moerr.NewInternalErrorNoCtx("substrait: invalid resolve audit hashes")
	}
	queryHash := sha256.Sum256(event.QueryID)
	record := resolveAuditRecord{
		Version: resolveAuditVersion, AccountID: event.AccountID,
		DatabaseID: event.DatabaseID, TableID: event.TableID,
		QueryIDSHA256:    hex.EncodeToString(queryHash[:]),
		ClientSPKISHA256: hex.EncodeToString(event.ClientSPKIHash),
		ReadRefSHA256:    hex.EncodeToString(event.ReadRefSHA256),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > maxResolveAuditRecordSize {
		return moerr.NewInternalErrorNoCtx("substrait: resolve audit record is too large")
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return a.admission.RunExclusive(ctx, a.admissionKey, func(exclusiveCtx context.Context) error {
		nonce := make([]byte, resolveAuditRandomBytes)
		if _, err := io.ReadFull(a.random, nonce); err != nil {
			return moerr.NewInternalErrorNoCtxf("substrait: create resolve audit identity: %v", err)
		}
		recordName := a.now().UTC().Format("20060102T150405.000000000Z") +
			"-" + hex.EncodeToString(nonce) + ".json"
		state := a.states.state(a.admissionKey, a.recordsPerPartition, a.retainedPartitions)
		stateConsistent := false
		defer func() {
			if !stateConsistent {
				state.invalidate()
			}
		}()
		if !state.loaded {
			partitions, identities, err := a.loadPartitions(exclusiveCtx)
			if err != nil {
				return err
			}
			state.partitions = partitions
			state.identities = identities
			state.loaded = true
		}
		if _, exists := state.identities[recordName]; exists {
			stateConsistent = true
			return moerr.NewInternalErrorNoCtx("substrait: resolve audit identity collision")
		}

		var generation uint64 = 1
		if len(state.partitions) > 0 {
			latest := &state.partitions[len(state.partitions)-1]
			if len(latest.records) < a.recordsPerPartition {
				name := path.Join(latest.name, recordName)
				if err := a.writeOnce(exclusiveCtx, name, payload); err != nil {
					return err
				}
				latest.records = append(latest.records, name)
				state.identities[recordName] = struct{}{}
				stateConsistent = true
				return nil
			}
			if latest.generation == ^uint64(0) {
				return moerr.NewInternalErrorNoCtx("substrait: resolve audit partition generation exhausted")
			}
			generation = latest.generation + 1
		}

		// Retention runs before publication, so the hard object quota is never
		// exceeded. A cleanup or subsequent write failure denies this resolve;
		// the next call reconstructs the exact durable state from FileService.
		deleteOldest := len(state.partitions) == a.retainedPartitions
		if deleteOldest {
			if err := a.deletePartition(exclusiveCtx, state.partitions[0]); err != nil {
				return err
			}
		}
		partitionName := path.Join(a.partitionsPrefix(), formatResolveAuditPartition(generation))
		name := path.Join(partitionName, recordName)
		if err := a.writeOnce(exclusiveCtx, name, payload); err != nil {
			return err
		}
		if deleteOldest {
			for _, deleted := range state.partitions[0].records {
				delete(state.identities, path.Base(deleted))
			}
			state.partitions = state.partitions[1:]
		}
		state.partitions = append(state.partitions, resolveAuditPartition{
			generation: generation,
			name:       partitionName,
			records:    []string{name},
		})
		state.identities[recordName] = struct{}{}
		stateConsistent = true
		return nil
	})
}

// loadPartitions is both restart recovery and durable quota admission. It
// rejects rather than retaining or scanning beyond the configured journal
// bound. Recovered identities preserve write-once collision behavior across
// rollover. The bounded state cache means this scan occurs on first use or
// after an ambiguous failure, not on every resolve.
func (a *fileServiceResolveAuditRecorder) loadPartitions(
	ctx context.Context,
) ([]resolveAuditPartition, map[string]struct{}, error) {
	partitions := make([]resolveAuditPartition, 0, a.retainedPartitions)
	identities := make(map[string]struct{}, a.recordsPerPartition*a.retainedPartitions)
	for entry, err := range a.fs.List(ctx, a.partitionsPrefix()) {
		if err != nil {
			return nil, nil, err
		}
		if entry == nil || !entry.IsDir {
			return nil, nil, moerr.NewInternalErrorNoCtx("substrait: invalid resolve audit partition")
		}
		generation, ok := parseResolveAuditPartition(entry.Name)
		if !ok {
			return nil, nil, moerr.NewInternalErrorNoCtxf(
				"substrait: invalid resolve audit partition %q", entry.Name)
		}
		if len(partitions) == a.retainedPartitions {
			return nil, nil, moerr.NewInternalErrorNoCtx("substrait: resolve audit partition quota exceeded")
		}
		partitionName := path.Join(a.partitionsPrefix(), entry.Name)
		partition := resolveAuditPartition{
			generation: generation,
			name:       partitionName,
			records:    make([]string, 0, a.recordsPerPartition),
		}
		for record, listErr := range a.fs.List(ctx, partitionName) {
			if listErr != nil {
				return nil, nil, listErr
			}
			if record == nil || record.IsDir || !validResolveAuditRecordName(record.Name) ||
				record.Size <= 0 || record.Size > maxResolveAuditRecordSize {
				return nil, nil, moerr.NewInternalErrorNoCtxf(
					"substrait: invalid resolve audit record in partition %q", entry.Name)
			}
			if len(partition.records) == a.recordsPerPartition {
				return nil, nil, moerr.NewInternalErrorNoCtxf(
					"substrait: resolve audit partition %q exceeded its quota", entry.Name)
			}
			if _, duplicate := identities[record.Name]; duplicate {
				return nil, nil, moerr.NewInternalErrorNoCtx("substrait: duplicate resolve audit identity")
			}
			identities[record.Name] = struct{}{}
			partition.records = append(partition.records, path.Join(partitionName, record.Name))
		}
		partitions = append(partitions, partition)
	}
	sort.Slice(partitions, func(i, j int) bool {
		return partitions[i].generation < partitions[j].generation
	})
	for i := 1; i < len(partitions); i++ {
		if partitions[i-1].generation == partitions[i].generation {
			return nil, nil, moerr.NewInternalErrorNoCtx("substrait: duplicate resolve audit partition")
		}
	}
	return partitions, identities, nil
}

func (a *fileServiceResolveAuditRecorder) deletePartition(
	ctx context.Context,
	partition resolveAuditPartition,
) error {
	for start := 0; start < len(partition.records); start += resolveAuditDeleteBatchSize {
		end := min(start+resolveAuditDeleteBatchSize, len(partition.records))
		// A multi-object delete may have stopped at a missing entry. Treat every
		// error as ambiguous so no new partition can be published while an old
		// object might remain and exceed the hard quota.
		if err := a.fs.Delete(ctx, partition.records[start:end]...); err != nil {
			return err
		}
	}
	return nil
}

func (a *fileServiceResolveAuditRecorder) writeOnce(
	ctx context.Context,
	name string,
	payload []byte,
) error {
	return a.fs.Write(ctx, fileservice.IOVector{
		FilePath: name,
		Entries: []fileservice.IOEntry{{
			Offset: 0, Size: int64(len(payload)), Data: payload,
		}},
	})
}

func (a *fileServiceResolveAuditRecorder) partitionsPrefix() string {
	return path.Join(a.prefix, "partitions")
}

func formatResolveAuditPartition(generation uint64) string {
	return fmt.Sprintf("%0*d", resolveAuditPartitionNameWidth, generation)
}

func parseResolveAuditPartition(name string) (uint64, bool) {
	if len(name) != resolveAuditPartitionNameWidth {
		return 0, false
	}
	generation, err := strconv.ParseUint(name, 10, 64)
	return generation, err == nil && generation > 0 && formatResolveAuditPartition(generation) == name
}

func validResolveAuditRecordName(name string) bool {
	const timestampBytes = len("20060102T150405.000000000Z")
	const nonceHexBytes = resolveAuditRandomBytes * 2
	if len(name) != timestampBytes+1+nonceHexBytes+len(".json") ||
		name[timestampBytes] != '-' || !strings.HasSuffix(name, ".json") {
		return false
	}
	if _, err := time.Parse("20060102T150405.000000000Z", name[:timestampBytes]); err != nil {
		return false
	}
	nonce := name[timestampBytes+1 : timestampBytes+1+nonceHexBytes]
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == resolveAuditRandomBytes && hex.EncodeToString(decoded) == nonce
}

var _ ResolveAuditRecorder = (*fileServiceResolveAuditRecorder)(nil)
