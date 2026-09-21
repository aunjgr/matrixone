// Copyright 2021 - 2022 Matrix Origin
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
	"time"

	"github.com/matrixorigin/matrixone/pkg/bootstrap"
	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/common/morpc"
	"github.com/matrixorigin/matrixone/pkg/defines"
	"github.com/matrixorigin/matrixone/pkg/fileservice"
	"github.com/matrixorigin/matrixone/pkg/lockservice"
	"github.com/matrixorigin/matrixone/pkg/logservice"
	logservicepb "github.com/matrixorigin/matrixone/pkg/pb/logservice"
	qclient "github.com/matrixorigin/matrixone/pkg/queryservice/client"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/taskservice"
	"github.com/matrixorigin/matrixone/pkg/txn/client"
	"github.com/matrixorigin/matrixone/pkg/udf"
	"github.com/matrixorigin/matrixone/pkg/util"
	"github.com/matrixorigin/matrixone/pkg/vm/engine"
	"go.uber.org/zap"
)

// Option option to create cn service
type Option func(*service)

const (
	DefaultSiriusTopologyCheckInterval = time.Second
	// CN bootstrap can legitimately take several seconds before the monitor is
	// scheduled. The durable storage-authority marker prevents a replacement
	// from opening during this bounded initial lease.
	DefaultSiriusTopologyValidity = 30 * time.Second
)

type SiriusTopologyValidator func(context.Context, logservice.CNHAKeeperClient) error

// WithLogger setup cn service's logger
func WithLogger(logger *zap.Logger) Option {
	return func(s *service) {
		s.logger = logger
	}
}

// WithTaskStorageFactory setup the special task storage factory
func WithTaskStorageFactory(factory taskservice.TaskStorageFactory) Option {
	return func(s *service) {
		s.task.storageFactory = factory
	}
}

// WithBootstrapOptions setup bootstrap options
func WithBootstrapOptions(options ...bootstrap.Option) Option {
	return func(s *service) {
		s.options.bootstrapOptions = options
	}
}

// WithTxnTraceData sets the root directory for transaction trace data. Each CN
// stores its trace data in a child directory keyed by its service UUID.
func WithTxnTraceData(traceDataPath string) Option {
	return func(s *service) {
		s.options.traceDataPath = traceDataPath
	}
}

// WithSiriusReadDependencies supplies the storage-owned, GC-protected lease
// authority and, for Flight, its durable resolve auditor. Embedded/local
// recovery does not resolve over the network and may pass a nil auditor. CN
// startup still constructs and owns both Flight mTLS endpoints. Keeping these
// dependencies explicit prevents an unsafe process-local GC protector from
// being created as a fallback.
func WithSiriusReadDependencies(leases *substrait.LeaseManager, auditor substrait.ResolveAuditRecorder) Option {
	return func(s *service) {
		s.options.siriusLeases = leases
		s.options.siriusAuditor = auditor
	}
}

// WithSiriusLeaseManagerCapability supplies revocable proof that the injected
// manager still belongs to the launcher-verified live TAE storage generation.
// Embedded TAE requires it; embedded MO retains it when local recovery wiring
// is present so topology revocation also closes that runtime's admission.
func WithSiriusLeaseManagerCapability(capability *substrait.LeaseManagerCapability) Option {
	return func(s *service) {
		s.options.siriusCapability = capability
	}
}

// WithSiriusTopologyValidator installs the authoritative post-start HAKeeper
// fence. A local manager capability without this validator cannot be renewed
// and expires fail closed.
func WithSiriusTopologyValidator(validator SiriusTopologyValidator) Option {
	return func(s *service) {
		s.options.siriusTopologyValidator = validator
	}
}

// WithSiriusTopologyRenewalHandoff transfers the launcher-owned construction
// renewal loop to the CN service. The service stops it only after its own
// authoritative monitor is live, or during failed-start cleanup.
func WithSiriusTopologyRenewalHandoff(handoff *substrait.LeaseManagerCapabilityHandoff) Option {
	return func(s *service) {
		s.options.siriusTopologyHandoff = handoff
	}
}

// RequiresSiriusCoLocatedTAE reports whether cfg requests the direct embedded
// TAE path. It deliberately examines only the explicit selector and does not
// mutate defaults or treat a disabled Sirius section as an active capability.
func RequiresSiriusCoLocatedTAE(cfg *Config) bool {
	return cfg != nil && cfg.Sirius.Enabled &&
		cfg.Sirius.Backend == "embedded" && cfg.Sirius.InputMode == "tae"
}

// VerifySiriusCoLocatedTAE records launcher-owned proof that direct TAE is
// confined to one static process containing exactly one TAE TN shard and one
// CN, and that the launcher installed the storage-owned lease-manager handoff.
// The proof cannot be decoded from TOML.
func VerifySiriusCoLocatedTAE(cfg *Config, verified bool) error {
	if cfg == nil {
		return nil
	}
	cfg.Sirius.coLocatedTAEVerified = false
	if !RequiresSiriusCoLocatedTAE(cfg) {
		return nil
	}
	if !verified {
		return moerr.NewBadConfigNoCtx("embedded Sirius TAE input requires launcher-verified one-TN/one-shard/one-CN co-location")
	}
	cfg.Sirius.coLocatedTAEVerified = true
	return nil
}

// VerifySiriusBenchmarkNoGC records the launcher-owned proof that the paired
// TN has disabled GC. CN cannot discover that fact through its normal service
// API, so Sirius startup refuses the benchmark adapter unless a top-level
// launcher calls this helper after checking the actual TN configuration.
func VerifySiriusBenchmarkNoGC(cfg *Config, tnGCDisabled bool) error {
	if cfg == nil {
		return nil
	}
	cfg.Sirius.benchmarkGCDisabled = false
	if !cfg.Sirius.BenchmarkNoGC {
		return nil
	}
	if !tnGCDisabled {
		return moerr.NewBadConfigNoCtx("Sirius benchmark-no-gc requires launcher-verified TN GCCfg disable-gc=true")
	}
	cfg.Sirius.benchmarkGCDisabled = true
	return nil
}

// WithMessageHandle setup message handle
func WithMessageHandle(f func(ctx context.Context,
	cnAddr string,
	message morpc.Message,
	cs morpc.ClientSession,
	engine engine.Engine,
	fs fileservice.FileService,
	lockService lockservice.LockService,
	queryClient qclient.QueryClient,
	hakeeper logservice.CNHAKeeperClient,
	udfService udf.Service,
	cli client.TxnClient,
	aicm *defines.AutoIncrCacheManager,
	mAcquirer func() morpc.Message) error) Option {
	return func(s *service) {
		s.requestHandler = f
	}
}

// WithConfigData saves the data from the config file
func WithConfigData(data map[string]*logservicepb.ConfigItem) Option {
	return func(s *service) {
		if s.config == nil {
			s.config = util.NewConfigData(data)
		} else {
			util.MergeConfig(s.config, data)
		}
	}
}
