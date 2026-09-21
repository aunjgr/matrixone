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

package tnservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/fileservice"
	logservicepb "github.com/matrixorigin/matrixone/pkg/pb/logservice"
	"github.com/matrixorigin/matrixone/pkg/pb/metadata"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/options"
)

// SiriusTAELeaseStorageIdentity identifies the exact live replica generation
// authorized to serve local Sirius reads. The durable journal namespace stays
// shard-stable, but launcher authority must not survive replica replacement.
func SiriusTAELeaseStorageIdentity(shard metadata.TNShard) string {
	return fmt.Sprintf("tae-tn-shard/%d/replica/%d", shard.ShardID, shard.ReplicaID)
}

// ValidateSiriusTAELiveTopology makes HAKeeper's live view, rather than the
// launch TOML, the final topology authority before a CN receives direct access
// to a process-local TAE generation.
func ValidateSiriusTAELiveTopology(
	details logservicepb.ClusterDetails,
	expectedTNUUID string,
	expectedStorageIdentity string,
) error {
	if expectedTNUUID == "" || expectedStorageIdentity == "" {
		return moerr.NewBadConfigNoCtx("invalid co-located Sirius TAE topology identity")
	}
	live := make([]logservicepb.TNStore, 0, 1)
	for _, store := range details.TNStores {
		if store.State == logservicepb.NormalState {
			live = append(live, store)
		}
	}
	if len(live) != 1 || live[0].UUID != expectedTNUUID || len(live[0].Shards) != 1 {
		return moerr.NewBadConfigNoCtx("live topology is not the launcher-verified one-TN/one-shard Sirius topology")
	}
	shard := metadata.TNShard{TNShardRecord: metadata.TNShardRecord{
		ShardID: live[0].Shards[0].ShardID,
	}, ReplicaID: live[0].Shards[0].ReplicaID}
	if SiriusTAELeaseStorageIdentity(shard) != expectedStorageIdentity {
		return moerr.NewBadConfigNoCtx("live TN shard does not match the published Sirius storage generation")
	}
	return nil
}

func siriusTAELeaseJournalPrefix(shard metadata.TNShard) string {
	return fmt.Sprintf("sirius/read-leases/tae-tn-shard-%d", shard.ShardID)
}

type siriusTAELeaseBootstrap struct {
	broker      *substrait.LeaseManagerBroker
	shard       metadata.TNShard
	capacity    int
	ownerUUID   string
	standalone  bool
	publication *substrait.LeaseManagerPublication
	reconciled  bool
	skipped     bool
}

type siriusTAEStorageAuthority struct {
	Version                 uint8  `json:"version"`
	TNUUID                  string `json:"tn_uuid"`
	ShardID                 uint64 `json:"shard_id"`
	ReplicaID               uint64 `json:"replica_id"`
	StorageGenerationSHA256 string `json:"storage_generation_sha256"`
}

func (s *store) newSiriusTAELeaseBootstrap(
	shard metadata.TNShard,
) (*siriusTAELeaseBootstrap, error) {
	if s == nil || s.cfg == nil {
		return nil, nil
	}
	return newSiriusTAELeaseBootstrapForStore(
		s.options.siriusLeaseBroker,
		shard,
		s.cfg.Txn.Storage.SiriusReadLeaseCapacity,
		s.cfg.UUID,
		s.cfg.InStandalone,
	)
}

func newSiriusTAELeaseBootstrap(
	broker *substrait.LeaseManagerBroker,
	shard metadata.TNShard,
	capacity int,
) (*siriusTAELeaseBootstrap, error) {
	return newSiriusTAELeaseBootstrapForStore(
		broker, shard, capacity, "test-tn", true)
}

func newSiriusTAELeaseBootstrapForStore(
	broker *substrait.LeaseManagerBroker,
	shard metadata.TNShard,
	capacity int,
	ownerUUID string,
	standalone bool,
) (*siriusTAELeaseBootstrap, error) {
	if capacity <= 0 || capacity > MaxSiriusReadLeaseCapacity {
		return nil, moerr.NewInternalErrorNoCtx("invalid co-located TAE lease bootstrap configuration")
	}
	if ownerUUID == "" {
		return nil, moerr.NewInternalErrorNoCtx("invalid TAE storage authority owner")
	}
	if broker != nil && !standalone {
		return nil, moerr.NewBadConfigNoCtx("Sirius TAE storage authority requires a co-located standalone TN")
	}
	return &siriusTAELeaseBootstrap{
		broker: broker, shard: shard, capacity: capacity,
		ownerUUID: ownerUUID, standalone: standalone,
	}, nil
}

func (b *siriusTAELeaseBootstrap) bootstrap(
	ctx context.Context,
	bootstrap options.PreGCBootstrapContext,
) error {
	if b == nil || bootstrap.SharedFileService == nil || bootstrap.Protector == nil ||
		len(bootstrap.StorageGenerationSHA256) != sha256.Size ||
		bootstrap.Shard.ShardID != b.shard.ShardID ||
		bootstrap.Shard.LogShardID != b.shard.LogShardID ||
		bootstrap.Shard.ReplicaID != b.shard.ReplicaID {
		return moerr.NewInternalErrorNoCtx("invalid co-located TAE pre-GC bootstrap context")
	}
	authorityExists, err := b.ensureStorageAuthority(
		ctx, bootstrap.SharedFileService, bootstrap.StorageGenerationSHA256)
	if err != nil {
		return err
	}
	if b.broker == nil && !b.standalone && !authorityExists {
		b.skipped = true
		return nil
	}
	journal, err := substrait.NewSingleProcessFileServiceLeaseJournal(
		bootstrap.SharedFileService,
		siriusTAELeaseJournalPrefix(bootstrap.Shard),
	)
	if err != nil {
		return err
	}
	manager := substrait.NewPersistentLeaseManager(
		b.capacity,
		bootstrap.Protector,
		journal,
	)
	if err := manager.Replay(ctx); err != nil {
		return err
	}
	if b.broker == nil {
		pending, err := manager.ReconcileRestart(ctx, substrait.ReadConsumerEmbeddedTAE)
		if err != nil {
			return err
		}
		if len(pending) != 0 || len(manager.PendingExecutions()) != 0 {
			return moerr.NewInvalidStateNoCtx("unreconciled Flight reads remain after standalone lease recovery")
		}
		// ReconcileRestart terminally released every embedded record and would
		// have failed on any Flight record. The empty manager has no future CN
		// consumer in this legacy/disabled mode and need not be retained.
		b.reconciled = true
		return nil
	}
	b.publication, err = b.broker.Prepare(
		SiriusTAELeaseStorageIdentity(bootstrap.Shard),
		manager,
	)
	return err
}

func (b *siriusTAELeaseBootstrap) ensureStorageAuthority(
	ctx context.Context,
	fs fileservice.FileService,
	storageGenerationSHA256 []byte,
) (bool, error) {
	name := path.Join(siriusTAELeaseJournalPrefix(b.shard), "storage-authority.json")
	want := siriusTAEStorageAuthority{
		Version: 1, TNUUID: b.ownerUUID,
		ShardID: b.shard.ShardID, ReplicaID: b.shard.ReplicaID,
		StorageGenerationSHA256: hex.EncodeToString(storageGenerationSHA256),
	}
	read := func() (*siriusTAEStorageAuthority, error) {
		vector := fileservice.IOVector{
			FilePath: name, Entries: []fileservice.IOEntry{{Offset: 0, Size: -1}},
		}
		if err := fs.Read(ctx, &vector); err != nil {
			return nil, err
		}
		defer vector.Release()
		if len(vector.Entries) != 1 || len(vector.Entries[0].Data) == 0 || len(vector.Entries[0].Data) > 4096 {
			return nil, moerr.NewInvalidStateNoCtx("invalid Sirius TAE storage authority record")
		}
		var got siriusTAEStorageAuthority
		if err := json.Unmarshal(vector.Entries[0].Data, &got); err != nil {
			return nil, moerr.NewInvalidStateNoCtxf("decode Sirius TAE storage authority: %v", err)
		}
		return &got, nil
	}
	got, err := read()
	if moerr.IsMoErrCode(err, moerr.ErrFileNotFound) {
		if b.broker == nil {
			return false, nil
		}
		payload, marshalErr := json.Marshal(want)
		if marshalErr != nil {
			return false, marshalErr
		}
		err = fs.Write(ctx, fileservice.IOVector{
			FilePath: name,
			Entries:  []fileservice.IOEntry{{Offset: 0, Size: int64(len(payload)), Data: payload}},
		})
		if err == nil {
			return true, nil
		}
		if !moerr.IsMoErrCode(err, moerr.ErrFileAlreadyExists) {
			return false, err
		}
		got, err = read()
	}
	if err != nil {
		return false, err
	}
	if got.Version != want.Version || got.TNUUID != want.TNUUID ||
		got.ShardID != want.ShardID || got.ReplicaID != want.ReplicaID ||
		got.StorageGenerationSHA256 != want.StorageGenerationSHA256 {
		return false, moerr.NewInvalidStateNoCtx(
			"TAE shard is fenced by a different Sirius storage authority")
	}
	return true, nil
}

// finish is called exactly once with NewTAEStorage's terminal result. An open
// error aborts the unpublished token; success is the only path that publishes.
func (b *siriusTAELeaseBootstrap) finish(openErr error) error {
	if b == nil {
		return openErr
	}
	if b.skipped {
		return openErr
	}
	if openErr != nil {
		if b.publication == nil {
			return openErr
		}
		return errors.Join(openErr, b.publication.Abort())
	}
	if b.broker == nil {
		if !b.reconciled {
			return moerr.NewInternalErrorNoCtx("TAE storage opened without standalone lease reconciliation")
		}
		return nil
	}
	if b.publication == nil {
		return moerr.NewInternalErrorNoCtx("TAE storage opened without pre-GC lease bootstrap")
	}
	return b.publication.Publish()
}
