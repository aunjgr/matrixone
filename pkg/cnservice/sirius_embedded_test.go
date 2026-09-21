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

package cnservice

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/matrixorigin/matrixone/pkg/container/types"
	planpb "github.com/matrixorigin/matrixone/pkg/pb/plan"
	"github.com/matrixorigin/matrixone/pkg/sql/compile"
	"github.com/matrixorigin/matrixone/pkg/sql/compile/siriusbridge"
)

type embeddedRuntimeRecorder struct {
	reads                       []siriusbridge.Read
	manifestBytes               int
	manifestFirst, manifestLast byte
	prepareErr                  error
}

func (*embeddedRuntimeRecorder) Accepting() bool             { return true }
func (*embeddedRuntimeRecorder) Close(context.Context) error { return nil }
func (r *embeddedRuntimeRecorder) Prepare(_ context.Context, req siriusbridge.Request) (*siriusbridge.Query, error) {
	r.reads = req.Reads
	if len(req.Reads) != 0 && len(req.Reads[0].TAEManifest) != 0 {
		r.manifestBytes = len(req.Reads[0].TAEManifest)
		r.manifestFirst = req.Reads[0].TAEManifest[0]
		r.manifestLast = req.Reads[0].TAEManifest[len(req.Reads[0].TAEManifest)-1]
	}
	return new(siriusbridge.Query), r.prepareErr
}

func TestEmbeddedSiriusConfigurationDoesNotRequireFlight(t *testing.T) {
	config := SiriusConfig{Backend: "embedded", NativeConfigPath: "sirius.conf"}
	if err := validateSiriusEmbeddedConfig(&config); err != nil {
		t.Fatal(err)
	}
	if config.InputMode != "mo" || config.GPUStreams != 2 || config.MaxWaitingQueries != 16 {
		t.Fatalf("defaults: %+v", config)
	}
	tae := config
	tae.InputMode = "tae"
	tae.DataDir = t.TempDir()
	tae.RequestTimeout.Duration = time.Minute
	tae.CleanupTimeout.Duration = time.Second
	if err := validateSiriusEmbeddedConfig(&tae); err != nil {
		t.Fatal(err)
	}
	if tae.LeaseTTL.Duration != time.Minute+time.Second {
		t.Fatalf("TAE lease default: %+v", tae)
	}
	for _, modify := range []func(*SiriusConfig){
		func(c *SiriusConfig) { c.InputMode = "invalid" },
		func(c *SiriusConfig) { c.NativeConfigPath = "" },
		func(c *SiriusConfig) { c.GPUStreams = 129 },
		func(c *SiriusConfig) { c.MaxWaitingQueries = 17 },
		func(c *SiriusConfig) { c.BenchmarkNoGC = true },
	} {
		invalid := config
		modify(&invalid)
		if validateSiriusEmbeddedConfig(&invalid) == nil {
			t.Fatalf("accepted %+v", invalid)
		}
	}
	tae.DataDir = ""
	if validateSiriusEmbeddedConfig(&tae) == nil {
		t.Fatal("accepted embedded TAE without data-dir")
	}
}

func TestEmbeddedSiriusPrepareDoesNotRetainReadDescriptors(t *testing.T) {
	manifest := make([]byte, 8<<20)
	manifest[0], manifest[len(manifest)-1] = 0x5a, 0xa5
	producer := func(context.Context, compile.SiriusInput) error { return nil }
	request := compile.SiriusPrepareRequest{
		Plan:        []byte("sentinel plan"),
		OutputTypes: []planpb.Type{{Id: int32(types.T_int64), Width: 64}},
		Headings:    []string{"sentinel heading"},
		Release:     func(context.Context) error { return nil },
		Reads: []compile.SiriusReadDescriptor{
			{
				BindingID: 1, Database: "db", Table: "table", Schema: "schema",
				Columns:     []compile.SiriusReadColumn{{Name: "column"}},
				TAEManifest: manifest, DataRoot: "/sentinel/root",
			},
			{BindingID: 2, Producer: producer, TAEManifest: manifest, DataRoot: "/must/not/survive"},
		},
	}
	recorder := new(embeddedRuntimeRecorder)
	execution, err := (&embeddedBackend{native: recorder}).Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.reads) != 2 {
		t.Fatalf("prepared reads = %d, want 2", len(recorder.reads))
	}
	if recorder.manifestBytes != 8<<20 || recorder.manifestFirst != 0x5a || recorder.manifestLast != 0xa5 {
		t.Fatalf("native preparation did not receive the manifest sentinel: %+v", recorder)
	}
	if !reflect.DeepEqual(recorder.reads[0], siriusbridge.Read{}) {
		t.Fatalf("TAE descriptor retained after preparation: %+v", recorder.reads[0])
	}
	if recorder.reads[1].BindingID != 2 || recorder.reads[1].Producer == nil {
		t.Fatalf("MO producer ownership not retained: %+v", recorder.reads[1])
	}
	producerOnly := siriusbridge.Read{BindingID: recorder.reads[1].BindingID, Producer: recorder.reads[1].Producer}
	recorder.reads[1].Producer, producerOnly.Producer = nil, nil
	if !reflect.DeepEqual(recorder.reads[1], producerOnly) {
		t.Fatalf("MO descriptor retained after preparation: %+v", recorder.reads[1])
	}

	request.OutputTypes[0].Id = int32(types.T_bool)
	request.Headings[0] = "mutated"
	request.Plan = nil
	request.Reads = nil
	manifest = nil
	got := execution.(*embeddedExecution)
	if len(got.outputTypes) != 1 || got.outputTypes[0].Oid != types.T_int64 {
		t.Fatalf("output types changed with request: %+v", got.outputTypes)
	}
	if !reflect.DeepEqual(got.headings, []string{"sentinel heading"}) {
		t.Fatalf("headings changed with request: %q", got.headings)
	}
	for i := 0; i < reflect.TypeOf(*got).NumField(); i++ {
		fieldType := reflect.TypeOf(*got).Field(i).Type
		if fieldType == reflect.TypeOf(compile.SiriusPrepareRequest{}) ||
			fieldType == reflect.TypeOf([]compile.SiriusReadDescriptor{}) ||
			fieldType == reflect.TypeOf([]byte(nil)) ||
			fieldType == reflect.TypeOf((func(context.Context) error)(nil)) {
			t.Fatalf("execution retains preparation field %s", fieldType)
		}
	}

	failedRecorder := &embeddedRuntimeRecorder{prepareErr: errors.New("prepare failed")}
	_, err = (&embeddedBackend{native: failedRecorder}).Prepare(context.Background(), compile.SiriusPrepareRequest{
		Reads: []compile.SiriusReadDescriptor{{TAEManifest: []byte("failure sentinel"), DataRoot: "/failure/root"}},
	})
	if !errors.Is(err, failedRecorder.prepareErr) {
		t.Fatalf("Prepare error = %v, want %v", err, failedRecorder.prepareErr)
	}
	if len(failedRecorder.reads) != 1 || !reflect.DeepEqual(failedRecorder.reads[0], siriusbridge.Read{}) {
		t.Fatalf("failed preparation retained descriptor: %+v", failedRecorder.reads)
	}
}
