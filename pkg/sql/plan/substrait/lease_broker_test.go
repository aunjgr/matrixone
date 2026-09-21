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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func replayedBrokerTestManager(t *testing.T) *LeaseManager {
	t.Helper()
	manager := NewPersistentLeaseManager(1, new(fakeProtector), new(fakeLeaseJournal))
	require.NoError(t, manager.Replay(context.Background()))
	require.True(t, manager.DurableReady())
	return manager
}

func TestLeaseManagerBrokerPreparePublishAbort(t *testing.T) {
	broker := NewLeaseManagerBroker()
	manager := replayedBrokerTestManager(t)

	publication, err := broker.Prepare("tae-tn-shard/1", manager)
	require.NoError(t, err)
	_, _, err = broker.Acquire()
	require.ErrorContains(t, err, "not published")

	require.NoError(t, publication.Abort())
	_, _, err = broker.Acquire()
	require.ErrorContains(t, err, "not published")

	publication, err = broker.Prepare("tae-tn-shard/1", manager)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())
	acquired, identity, err := broker.Acquire()
	require.NoError(t, err)
	require.Same(t, manager, acquired)
	require.Equal(t, "tae-tn-shard/1", identity)
	require.NoError(t, publication.Abort(), "late abort must not clear a publication")
	acquired, _, err = broker.Acquire()
	require.NoError(t, err)
	require.Same(t, manager, acquired)
}

func TestLeaseManagerBrokerSecondGenerationSeals(t *testing.T) {
	broker := NewLeaseManagerBroker()
	first := replayedBrokerTestManager(t)
	publication, err := broker.Prepare("tae-tn-shard/1", first)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())

	_, err = broker.Prepare("tae-tn-shard/1", replayedBrokerTestManager(t))
	require.ErrorContains(t, err, "second TAE lease manager generation")
	_, _, err = broker.Acquire()
	require.ErrorContains(t, err, "sealed")
	require.ErrorContains(t, publication.Publish(), "already terminal")
}

func TestLeaseManagerBrokerConcurrentPrepareHasNoReplacementWinner(t *testing.T) {
	broker := NewLeaseManagerBroker()
	managers := []*LeaseManager{
		replayedBrokerTestManager(t),
		replayedBrokerTestManager(t),
	}
	start := make(chan struct{})
	publications := make(chan *LeaseManagerPublication, len(managers))
	errs := make(chan error, len(managers))
	var workers sync.WaitGroup
	for _, manager := range managers {
		workers.Add(1)
		go func(manager *LeaseManager) {
			defer workers.Done()
			<-start
			publication, err := broker.Prepare("tae-tn-shard/1", manager)
			publications <- publication
			errs <- err
		}(manager)
	}
	close(start)
	workers.Wait()
	close(publications)
	close(errs)

	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	for publication := range publications {
		if publication != nil {
			require.ErrorContains(t, publication.Publish(), "superseded")
		}
	}
	_, _, err := broker.Acquire()
	require.ErrorContains(t, err, "sealed")
}

func TestLeaseManagerBrokerSealNeverReleasesProtection(t *testing.T) {
	broker := NewLeaseManagerBroker()
	manager := replayedBrokerTestManager(t)
	publication, err := broker.Prepare("tae-tn-shard/1", manager)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())

	broker.Seal()
	_, _, err = broker.Acquire()
	require.ErrorContains(t, err, "sealed")
	require.True(t, manager.DurableReady(), "seal must not mutate or release the manager")
}

func TestLeaseManagerCapabilityRevokesBeforeStorageTeardown(t *testing.T) {
	broker := NewLeaseManagerBroker()
	manager := replayedBrokerTestManager(t)
	publication, err := broker.Prepare("tae-tn-shard/1/replica/2", manager)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())
	capability, err := broker.AttestTopology("tae-tn-shard/1/replica/2", time.Minute)
	require.NoError(t, err)
	identity := capability.StorageIdentity()
	require.Equal(t, identity, capability.StorageIdentity())
	require.NoError(t, capability.Healthy())

	refuse, err := broker.RevokeStorage("tae-tn-shard/9/replica/9")
	require.NoError(t, err)
	require.False(t, refuse)
	require.NoError(t, capability.Healthy())

	refuse, err = broker.RevokeStorage(identity)
	require.NoError(t, err)
	require.True(t, refuse)
	require.ErrorContains(t, capability.Healthy(), "revoked")
	_, _, _, err = broker.AcquireCapability()
	require.ErrorContains(t, err, "sealed")
	refuse, err = broker.RevokeStorage(identity)
	require.NoError(t, err)
	require.True(t, refuse, "repeat removal remains refused before CN drain")

	broker.Seal()
	refuse, err = broker.RevokeStorage(identity)
	require.NoError(t, err)
	require.False(t, refuse, "CN drain authorizes orderly storage teardown")
	require.True(t, manager.DurableReady(), "revocation never removes active protection")
}

func TestLeaseManagerCapabilityExpiresWithoutSourceRemove(t *testing.T) {
	now := time.Unix(100, 0)
	broker := NewLeaseManagerBroker()
	broker.now = func() time.Time { return now }
	manager := replayedBrokerTestManager(t)
	identity := "tae-tn-shard/3/replica/4"
	publication, err := broker.Prepare(identity, manager)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())
	capability, err := broker.AttestTopology(identity, 10*time.Second)
	require.NoError(t, err)
	require.NoError(t, capability.Healthy())
	now = now.Add(11 * time.Second)
	require.ErrorContains(t, capability.Healthy(), "revoked")
	require.ErrorContains(t, capability.RenewTopology(time.Minute), "revoked")
	_, err = broker.AttestTopology(identity, time.Minute)
	require.ErrorContains(t, err, "already attested")
	require.True(t, manager.DurableReady(), "attestation expiry must retain the old protection owner")
}

func TestTopologyRenewalHandoffCoversSlowConstructionWithFakeClock(t *testing.T) {
	now := time.Unix(200, 0)
	broker := NewLeaseManagerBroker()
	broker.now = func() time.Time { return now }
	manager := replayedBrokerTestManager(t)
	identity := "tae-tn-shard/5/replica/6"
	publication, err := broker.Prepare(identity, manager)
	require.NoError(t, err)
	require.NoError(t, publication.Publish())
	capability, err := broker.AttestTopology(identity, 30*time.Second)
	require.NoError(t, err)
	handoff := &LeaseManagerCapabilityHandoff{
		capability: capability, validFor: 30 * time.Second,
	}
	for range 32 {
		now = now.Add(29 * time.Second)
		require.NoError(t, handoff.renew())
		require.NoError(t, capability.Healthy())
	}
	require.Greater(t, now.Sub(time.Unix(200, 0)), 15*time.Minute,
		"construction/replay bridge must not inherit request timeout")
	now = now.Add(31 * time.Second)
	require.ErrorContains(t, capability.Healthy(), "revoked")
}
