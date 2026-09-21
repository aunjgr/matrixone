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
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	storageGenerationFile = "SIRIUS-GENERATION"
	storageGenerationSize = 32
)

var readStorageGenerationMachineID = func() ([]byte, error) {
	value, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, err
	}
	value = []byte(strings.TrimSpace(string(value)))
	if len(value) == 0 {
		return nil, errors.New("empty machine identity")
	}
	return value, nil
}

// loadOrCreateStorageGeneration runs only after createDBLock has acquired the
// kernel F_WRLCK for dirname. The stable random token permits crash restart in
// the exact directory, while the machine and canonical-directory binding makes
// copied directories and cross-host rolling generations fail shared authority.
func loadOrCreateStorageGeneration(dirname string) ([]byte, error) {
	canonical, err := filepath.Abs(dirname)
	if err != nil {
		return nil, err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(canonical); resolveErr == nil {
		canonical = resolved
	}
	tokenPath := filepath.Join(canonical, storageGenerationFile)
	token, err := os.ReadFile(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		token = make([]byte, storageGenerationSize)
		if _, err = io.ReadFull(rand.Reader, token); err != nil {
			return nil, fmt.Errorf("create TAE storage generation: %w", err)
		}
		file, createErr := os.OpenFile(tokenPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create TAE storage generation file: %w", createErr)
		}
		_, writeErr := file.Write(token)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		dir, openErr := os.Open(canonical)
		if openErr != nil {
			return nil, openErr
		}
		syncErr := dir.Sync()
		closeErr = dir.Close()
		if syncErr != nil {
			return nil, syncErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	} else if err != nil {
		return nil, err
	}
	if len(token) != storageGenerationSize {
		return nil, fmt.Errorf("invalid TAE storage generation token size %d", len(token))
	}
	machineID, err := readStorageGenerationMachineID()
	if err != nil {
		return nil, fmt.Errorf("read TAE storage generation machine identity: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("matrixone/tae/storage-generation/v1\x00"))
	_, _ = h.Write(token)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(machineID)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(canonical))
	return h.Sum(nil), nil
}
