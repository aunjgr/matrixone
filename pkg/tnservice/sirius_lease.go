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
	"errors"
	"fmt"

	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/pb/metadata"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/options"
)

// SiriusTAELeaseStorageIdentity is stable across a replica relocation because
// durable read leases protect objects owned by the TN shard, not one replica
// process incarnation.
func SiriusTAELeaseStorageIdentity(shard metadata.TNShard) string {
	return fmt.Sprintf("tae-tn-shard/%d", shard.ShardID)
}

func siriusTAELeaseJournalPrefix(shard metadata.TNShard) string {
	return fmt.Sprintf("sirius/read-leases/tae-tn-shard-%d", shard.ShardID)
}

type siriusTAELeaseBootstrap struct {
	broker      *substrait.LeaseManagerBroker
	shard       metadata.TNShard
	capacity    int
	publication *substrait.LeaseManagerPublication
	reconciled  bool
}

func (s *store) newSiriusTAELeaseBootstrap(
	shard metadata.TNShard,
) (*siriusTAELeaseBootstrap, error) {
	if s == nil || s.cfg == nil || !s.cfg.InStandalone {
		return nil, nil
	}
	return newSiriusTAELeaseBootstrap(
		s.options.siriusLeaseBroker,
		shard,
		s.cfg.Txn.Storage.SiriusReadLeaseCapacity,
	)
}

func newSiriusTAELeaseBootstrap(
	broker *substrait.LeaseManagerBroker,
	shard metadata.TNShard,
	capacity int,
) (*siriusTAELeaseBootstrap, error) {
	if capacity <= 0 || capacity > MaxSiriusReadLeaseCapacity {
		return nil, moerr.NewInternalErrorNoCtx("invalid co-located TAE lease bootstrap configuration")
	}
	return &siriusTAELeaseBootstrap{broker: broker, shard: shard, capacity: capacity}, nil
}

func (b *siriusTAELeaseBootstrap) bootstrap(
	ctx context.Context,
	bootstrap options.PreGCBootstrapContext,
) error {
	if b == nil || bootstrap.SharedFileService == nil || bootstrap.Protector == nil ||
		bootstrap.Shard.ShardID != b.shard.ShardID ||
		bootstrap.Shard.LogShardID != b.shard.LogShardID ||
		bootstrap.Shard.ReplicaID != b.shard.ReplicaID {
		return moerr.NewInternalErrorNoCtx("invalid co-located TAE pre-GC bootstrap context")
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

// finish is called exactly once with NewTAEStorage's terminal result. An open
// error aborts the unpublished token; success is the only path that publishes.
func (b *siriusTAELeaseBootstrap) finish(openErr error) error {
	if b == nil {
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
