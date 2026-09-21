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

package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matrixorigin/matrixone/pkg/pb/metadata"
	gc "github.com/matrixorigin/matrixone/pkg/vm/engine/tae/db/gc/v3"
	"github.com/matrixorigin/matrixone/pkg/vm/engine/tae/options"
	"github.com/stretchr/testify/require"
)

func TestPreGCBootstrapProtectionExistsBeforeFirstGCOpportunity(t *testing.T) {
	dir := t.TempDir()
	shard := metadata.TNShard{
		TNShardRecord: metadata.TNShardRecord{ShardID: 7, LogShardID: 8},
		ReplicaID:     9,
	}
	readRef := bytes.Repeat([]byte{7}, 32)
	const objectName = "protected-at-open"
	var manager *gc.SyncProtectionManager
	hookCalls := 0
	opts := (&options.Options{
		Shard: shard,
		PreGCBootstrap: func(ctx context.Context, bootstrap options.PreGCBootstrapContext) error {
			hookCalls++
			require.Equal(t, shard.ShardID, bootstrap.Shard.ShardID)
			require.Equal(t, shard.LogShardID, bootstrap.Shard.LogShardID)
			require.Equal(t, shard.ReplicaID, bootstrap.Shard.ReplicaID)
			require.NotNil(t, bootstrap.SharedFileService)
			protector, ok := bootstrap.Protector.(gc.SidecarReadProtector)
			require.True(t, ok)
			manager = protector.Manager
			require.NotNil(t, manager)
			require.False(t, manager.IsGCRunning(), "GC must not start before bootstrap")
			return protector.Register(ctx, readRef, []string{objectName}, time.Now().Add(time.Hour))
		},
	}).FillDefaults(dir)

	tae, err := Open(context.Background(), dir, opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, tae.Close()) })
	require.Equal(t, 1, hookCalls)
	require.NotNil(t, manager)
	require.True(t, manager.IsProtected(objectName),
		"replayed protection must be visible when the cleaner gets its first work")
}

func TestPreGCBootstrapFailurePreventsOpenAndCleanerStart(t *testing.T) {
	dir := t.TempDir()
	bootstrapErr := errors.New("injected pre-GC bootstrap failure")
	var manager *gc.SyncProtectionManager
	opts := (&options.Options{
		PreGCBootstrap: func(_ context.Context, bootstrap options.PreGCBootstrapContext) error {
			protector, ok := bootstrap.Protector.(gc.SidecarReadProtector)
			require.True(t, ok)
			manager = protector.Manager
			require.False(t, manager.IsGCRunning())
			return bootstrapErr
		},
	}).FillDefaults(dir)

	_, err := Open(context.Background(), dir, opts)
	require.ErrorIs(t, err, bootstrapErr)
	require.NotNil(t, manager)
	require.False(t, manager.IsGCRunning())
	guard, guardErr := manager.BeginProtection()
	require.NoError(t, guardErr,
		"a failed hook must return before DiskCleaner.Start can take the GC barrier")
	guard.Close()
}
