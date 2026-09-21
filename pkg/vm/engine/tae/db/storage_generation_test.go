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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorageGenerationStableRestartAndDirectoryBinding(t *testing.T) {
	originalMachineID := readStorageGenerationMachineID
	readStorageGenerationMachineID = func() ([]byte, error) { return []byte("machine-a"), nil }
	t.Cleanup(func() { readStorageGenerationMachineID = originalMachineID })

	firstDir := t.TempDir()
	first, err := loadOrCreateStorageGeneration(firstDir)
	require.NoError(t, err)
	restarted, err := loadOrCreateStorageGeneration(firstDir)
	require.NoError(t, err)
	require.Equal(t, first, restarted, "crash restart in the same persistent directory reuses generation")

	secondDir := t.TempDir()
	second, err := loadOrCreateStorageGeneration(secondDir)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	token, err := os.ReadFile(filepath.Join(firstDir, storageGenerationFile))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(secondDir, storageGenerationFile), token, 0o600))
	copied, err := loadOrCreateStorageGeneration(secondDir)
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, copied), "copied token is fenced by canonical directory")

	readStorageGenerationMachineID = func() ([]byte, error) { return []byte("machine-b"), nil }
	crossHost, err := loadOrCreateStorageGeneration(firstDir)
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, crossHost), "copied directory is fenced by machine identity")
}

func TestStorageGenerationRejectsSameDirectoryOverlapAndAllowsRestart(t *testing.T) {
	dir := t.TempDir()
	lock, err := createDBLock(dir)
	require.NoError(t, err)
	command := func(expect string) error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStorageGenerationLockHelper$")
		cmd.Env = append(os.Environ(), "MO_STORAGE_GENERATION_LOCK_HELPER="+expect, "MO_STORAGE_GENERATION_LOCK_DIR="+dir)
		return cmd.Run()
	}
	require.NoError(t, command("blocked"), "overlapping process must be rejected by kernel directory lock")
	require.NoError(t, lock.Close())
	require.NoError(t, command("acquired"), "restart acquires the released same-directory lock")
}

func TestStorageGenerationLockHelper(t *testing.T) {
	mode := os.Getenv("MO_STORAGE_GENERATION_LOCK_HELPER")
	if mode == "" {
		return
	}
	lock, err := createDBLock(os.Getenv("MO_STORAGE_GENERATION_LOCK_DIR"))
	switch mode {
	case "blocked":
		if err == nil {
			_ = lock.Close()
			os.Exit(2)
		}
	case "acquired":
		if err != nil {
			os.Exit(3)
		}
		_ = lock.Close()
	default:
		os.Exit(4)
	}
}
