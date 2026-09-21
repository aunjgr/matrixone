// Copyright 2022 Matrix Origin
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

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fagongzi/goetty/v2"
	"go.uber.org/zap"

	"github.com/matrixorigin/matrixone/pkg/backup"
	"github.com/matrixorigin/matrixone/pkg/cnservice"
	"github.com/matrixorigin/matrixone/pkg/common/moerr"
	"github.com/matrixorigin/matrixone/pkg/common/stopper"
	"github.com/matrixorigin/matrixone/pkg/logservice"
	"github.com/matrixorigin/matrixone/pkg/logutil"
	logpb "github.com/matrixorigin/matrixone/pkg/pb/logservice"
	"github.com/matrixorigin/matrixone/pkg/pb/metadata"
	"github.com/matrixorigin/matrixone/pkg/sql/plan/substrait"
	"github.com/matrixorigin/matrixone/pkg/tnservice"
)

var (
	cnProxy                 goetty.Proxy
	launchStartService      = startService
	launchStartDynamic      = startDynamicCluster
	launchNewProxy          = goetty.NewProxy
	launchNewHAKeeperClient = logservice.NewCNHAKeeperClient
	launchSleep             = time.Sleep
	launchSignalNotify      = signal.Notify
	launchSignalStop        = signal.Stop
)

func startCluster(
	ctx context.Context,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
) error {
	if *launchFile == "" {
		panic("launch file not set")
	}

	cfg := &LaunchConfig{}
	if err := parseConfigFromFile(*launchFile, cfg); err != nil {
		return err
	}
	if err := validateLaunchManifest(cfg); err != nil {
		return err
	}

	if cfg.Dynamic.Enable {
		if err := rejectDynamicSiriusTAE(cfg.Dynamic); err != nil {
			return err
		}
		return launchStartDynamic(ctx, cfg, stopper, shutdownC)
	}
	launchPlan, err := prepareStaticSiriusLaunch(cfg)
	if err != nil {
		return err
	}

	/*
		When the mo started in local cluster, we save all config files.
		Because we can get all config files conveniently.
	*/
	backup.SaveLaunchConfigPath(backup.LaunchConfig, []string{*launchFile})
	backup.SaveLaunchConfigPath(backup.LogConfig, cfg.LogServiceConfigFiles)
	backup.SaveLaunchConfigPath(backup.DnConfig, cfg.TNServiceConfigsFiles)
	backup.SaveLaunchConfigPath(backup.CnConfig, cfg.CNServiceConfigsFiles)
	if err := startLogServiceCluster(ctx, cfg.LogServiceConfigFiles, stopper, shutdownC); err != nil {
		return err
	}
	tnGCDisabled, err := startTNServiceConfigs(ctx, launchPlan.tn, stopper, shutdownC, launchPlan.broker)
	if err != nil {
		return err
	}
	proxyOwns6001 := false
	if *withProxy {
		var err error
		proxyOwns6001, err = proxyServiceOwnsPort(cfg.ProxyServiceConfigsFiles, 6001)
		if err != nil {
			return err
		}
	}
	if err := startCNServiceConfigs(ctx, launchPlan.cn, stopper, shutdownC, tnGCDisabled, proxyOwns6001, launchPlan.broker); err != nil {
		return err
	}
	if *withProxy {
		backup.SaveLaunchConfigPath(backup.ProxyConfig, cfg.ProxyServiceConfigsFiles)
		if err := startProxyServiceCluster(ctx, cfg.ProxyServiceConfigsFiles, stopper, shutdownC); err != nil {
			return err
		}
	}
	if err := startPythonUdfServiceCluster(ctx, cfg.PythonUdfServiceConfigsFiles, stopper, shutdownC); err != nil {
		return err
	}
	return nil
}

type staticSiriusLaunch struct {
	tn     []*Config
	cn     []*Config
	broker *substrait.LeaseManagerBroker
}

func prepareStaticSiriusLaunch(cfg *LaunchConfig) (*staticSiriusLaunch, error) {
	tnConfigs, err := loadLaunchServiceConfigs(cfg.TNServiceConfigsFiles, metadata.ServiceType_TN)
	if err != nil {
		return nil, err
	}
	cnConfigs, err := loadLaunchServiceConfigs(cfg.CNServiceConfigsFiles, metadata.ServiceType_CN)
	if err != nil {
		return nil, err
	}
	logConfigs, err := loadLaunchServiceConfigs(cfg.LogServiceConfigFiles, metadata.ServiceType_LOG)
	if err != nil {
		return nil, err
	}
	if len(tnConfigs) == 0 {
		return nil, moerr.NewBadConfigNoCtx("DN service config not set")
	}
	if len(cnConfigs) == 0 {
		return nil, moerr.NewBadConfigNoCtx("CN service config not set")
	}

	directTAE := false
	for _, cn := range cnConfigs {
		directTAE = directTAE || cnservice.RequiresSiriusCoLocatedTAE(&cn.CN)
	}
	shards, shardConfigurationFound, err := configuredLaunchTNShards(logConfigs)
	if err != nil {
		return nil, err
	}
	taeTN := false
	if len(tnConfigs) == 1 {
		backend := tnConfigs[0].getTNServiceConfig().Txn.Storage.Backend
		taeTN = backend == "" || backend == tnservice.StorageTAE
	}
	safe := len(tnConfigs) == 1 && len(cnConfigs) == 1 && taeTN &&
		shardConfigurationFound && shards == 1
	if directTAE && !safe {
		return nil, moerr.NewBadConfigNoCtx(
			"embedded Sirius TAE input requires a static one-TAE-TN/one-shard/one-CN launch",
		)
	}

	plan := &staticSiriusLaunch{tn: tnConfigs, cn: cnConfigs}
	if safe {
		plan.broker = substrait.NewLeaseManagerBroker()
	}
	for _, cn := range cnConfigs {
		if err := cnservice.VerifySiriusCoLocatedTAE(&cn.CN, plan.broker != nil); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

func configuredLaunchTNShards(configs []*Config) (uint64, bool, error) {
	var shards uint64
	found := false
	for _, cfg := range configs {
		bootstrap := cfg.getLogServiceConfig().BootstrapConfig
		if !bootstrap.BootstrapCluster {
			continue
		}
		if !found {
			shards = bootstrap.NumOfTNShards
			found = true
			continue
		}
		if bootstrap.NumOfTNShards != shards {
			return 0, false, moerr.NewBadConfigNoCtx("inconsistent launch num-of-tn-shards")
		}
	}
	return shards, found, nil
}

func rejectDynamicSiriusTAE(cfg Dynamic) error {
	if cfg.ServiceCount == 0 || cfg.CNTemplate == "" {
		return nil
	}
	templateBytes, err := os.ReadFile(cfg.CNTemplate)
	if err != nil {
		return err
	}
	// Match genDynamicCNConfigs' six substitutions without writing a child
	// config or starting infrastructure merely to inspect the requested mode.
	formatted := fmt.Sprintf(string(templateBytes), 0, 18000, 0, 0, 16001, 0)
	cn := NewConfig()
	if err := parseFromString(formatted, cn); err != nil {
		return err
	}
	if cnservice.RequiresSiriusCoLocatedTAE(&cn.CN) {
		return moerr.NewBadConfigNoCtx("dynamic CN launch does not support embedded Sirius TAE input")
	}
	return nil
}

func startLogServiceCluster(
	ctx context.Context,
	files []string,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
) error {
	if len(files) == 0 {
		return moerr.NewBadConfig(context.Background(), "Log service config not set")
	}

	configs, err := loadLaunchServiceConfigs(files, metadata.ServiceType_LOG)
	if err != nil {
		return err
	}
	for _, cfg := range configs {
		if err := launchStartService(ctx, cfg, stopper, shutdownC); err != nil {
			return err
		}
	}
	return nil
}

func startTNServiceCluster(
	ctx context.Context,
	files []string,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
) (bool, error) {
	if len(files) == 0 {
		return false, moerr.NewBadConfig(context.Background(), "DN service config not set")
	}

	configs, err := loadLaunchServiceConfigs(files, metadata.ServiceType_TN)
	if err != nil {
		return false, err
	}
	return startTNServiceConfigs(ctx, configs, stopper, shutdownC, nil)
}

func startTNServiceConfigs(
	ctx context.Context,
	configs []*Config,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
	broker *substrait.LeaseManagerBroker,
) (bool, error) {
	gcDisabled := true
	// mo boosting in standalone mode
	for _, cfg := range configs {
		cfg.IsStandalone = true
		cfg.siriusLeaseBroker = broker
		gcDisabled = gcDisabled && cfg.getTNServiceConfig().GCCfg.DisableGC
	}
	for _, cfg := range configs {
		if err := launchStartService(ctx, cfg, stopper, shutdownC); err != nil {
			return false, err
		}
	}
	return gcDisabled, nil
}

func startCNServiceCluster(
	ctx context.Context,
	files []string,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
	tnGCDisabled bool,
	proxyOwns6001 ...bool,
) error {
	if len(files) == 0 {
		return moerr.NewBadConfig(context.Background(), "CN service config not set")
	}
	configs, err := loadLaunchServiceConfigs(files, metadata.ServiceType_CN)
	if err != nil {
		return err
	}
	owns6001 := len(proxyOwns6001) > 0 && proxyOwns6001[0]
	return startCNServiceConfigs(ctx, configs, stopper, shutdownC, tnGCDisabled, owns6001, nil)
}

func startCNServiceConfigs(
	ctx context.Context,
	configs []*Config,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
	tnGCDisabled bool,
	proxyOwns6001 bool,
	broker *substrait.LeaseManagerBroker,
) error {
	upstreams := make([]string, 0, len(configs))

	for _, cfg := range configs {
		cfg.benchmarkTNNoGC = tnGCDisabled
		cfg.siriusLeaseBroker = broker
		upstreams = append(upstreams, fmt.Sprintf("127.0.0.1:%d", cfg.getCNServiceConfig().Frontend.Port))
	}
	for _, cfg := range configs {
		if err := launchStartService(ctx, cfg, stopper, shutdownC); err != nil {
			return err
		}
	}

	if shouldStartBuiltinCNProxy(len(upstreams), *withProxy, proxyOwns6001) {
		// Keep the legacy 6001 entrypoint when the configured Proxy does not own it.
		proxy := launchNewProxy("0.0.0.0:6001", logutil.GetGlobalLogger().Named("mysql-proxy"))
		for _, address := range upstreams {
			proxy.AddUpStream(address, time.Second*10)
		}
		if err := proxy.Start(); err != nil {
			return err
		}
		cnProxy = proxy
	}
	return nil
}

func validateLaunchServiceConfigType(cfg *Config, file string, expected metadata.ServiceType) error {
	actual, err := cfg.getServiceType()
	if err != nil {
		return err
	}
	if actual != expected {
		return moerr.NewBadConfigf(
			context.Background(),
			"%s service config %q has service-type=%s, expected %s",
			expected.String(), file, actual.String(), expected.String())
	}
	return nil
}

func loadLaunchServiceConfigs(files []string, expected metadata.ServiceType) ([]*Config, error) {
	configs := make([]*Config, 0, len(files))
	for _, file := range files {
		cfg := NewConfig()
		if err := parseConfigFromFile(file, cfg); err != nil {
			return nil, err
		}
		if err := validateLaunchServiceConfigType(cfg, file, expected); err != nil {
			return nil, err
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}

func validateLaunchManifest(cfg *LaunchConfig) error {
	manifests := []struct {
		files    []string
		expected metadata.ServiceType
	}{
		{cfg.LogServiceConfigFiles, metadata.ServiceType_LOG},
		{cfg.TNServiceConfigsFiles, metadata.ServiceType_TN},
		{cfg.CNServiceConfigsFiles, metadata.ServiceType_CN},
		{cfg.ProxyServiceConfigsFiles, metadata.ServiceType_PROXY},
		{cfg.PythonUdfServiceConfigsFiles, metadata.ServiceType_PYTHON_UDF},
	}
	for _, manifest := range manifests {
		if _, err := loadLaunchServiceConfigs(manifest.files, manifest.expected); err != nil {
			return err
		}
	}
	return nil
}

func shouldStartBuiltinCNProxy(upstreamCount int, proxyServiceEnabled bool, proxyOwns6001 ...bool) bool {
	owns6001 := len(proxyOwns6001) > 0 && proxyOwns6001[0]
	return upstreamCount > 1 && (!proxyServiceEnabled || !owns6001)
}

func proxyServiceOwnsPort(files []string, port int) (bool, error) {
	for _, file := range files {
		cfg := NewConfig()
		if err := parseConfigFromFile(file, cfg); err != nil {
			return false, err
		}
		proxyCfg := cfg.getProxyConfig()
		proxyCfg.FillDefault()
		configuredPort, err := proxyListenPort(proxyCfg.ListenAddress)
		if err != nil {
			return false, err
		}
		if configuredPort == fmt.Sprint(port) {
			return true, nil
		}
	}
	return false, nil
}

// proxyListenPort follows pkg/proxy's listener address contract. Unix
// listeners have no TCP port and therefore cannot own the built-in 6001
// endpoint; in that case the legacy TCP proxy remains enabled.
func proxyListenPort(address string) (string, error) {
	if !strings.Contains(address, "//") {
		_, port, err := net.SplitHostPort(address)
		return port, err
	}
	u, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(u.Scheme, "unix") {
		return "", nil
	}
	_, port, err := net.SplitHostPort(u.Host)
	return port, err
}

func startProxyServiceCluster(
	ctx context.Context,
	files []string,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
) error {
	if len(files) == 0 {
		return moerr.NewBadConfig(context.Background(), "Proxy service config not set")
	}

	configs, err := loadLaunchServiceConfigs(files, metadata.ServiceType_PROXY)
	if err != nil {
		return err
	}
	for _, cfg := range configs {
		if err := launchStartService(ctx, cfg, stopper, shutdownC); err != nil {
			return err
		}
	}

	return nil
}

func startPythonUdfServiceCluster(
	ctx context.Context,
	files []string,
	stopper *stopper.Stopper,
	shutdownC chan struct{},
) error {
	if len(files) == 0 {
		return nil
	}

	configs, err := loadLaunchServiceConfigs(files, metadata.ServiceType_PYTHON_UDF)
	if err != nil {
		return err
	}
	for _, cfg := range configs {
		if err := launchStartService(ctx, cfg, stopper, shutdownC); err != nil {
			return err
		}
	}
	return nil
}

func waitHAKeeperReady(
	service string,
	cfg logservice.HAKeeperClientConfig,
) (logservice.CNHAKeeperClient, error) {
	getClient := func() (logservice.CNHAKeeperClient, error) {
		ctx, cancel := context.WithTimeoutCause(context.Background(), time.Second*5, moerr.CauseWaitHAKeeperReader1)
		defer cancel()
		client, err := launchNewHAKeeperClient(ctx, service, cfg)
		if err != nil {
			err = moerr.AttachCause(ctx, err)
			logutil.Errorf("hakeeper not ready, err: %v", err)
			return nil, err
		}
		return client, nil
	}

	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Minute*5, moerr.CauseWaitHAKeeperReader2)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil, errors.Join(moerr.NewInternalErrorNoCtx("wait hakeeper ready timeout"), context.Cause(ctx))
		default:
			client, err := getClient()
			if err == nil {
				return client, nil
			}
			launchSleep(time.Second)
		}
	}
}

func waitHAKeeperRunning(client logservice.CNHAKeeperClient) error {
	ctx, cancel := context.WithTimeoutCause(context.TODO(), time.Minute*2, moerr.CauseWaitHAKeeperRunning)
	defer cancel()

	// wait HAKeeper running
	for {
		state, err := client.GetClusterState(ctx)
		if errors.Is(err, context.DeadlineExceeded) {
			return moerr.AttachCause(ctx, err)
		}
		if moerr.IsMoErrCode(err, moerr.ErrNoHAKeeper) ||
			state.State != logpb.HAKeeperRunning {
			// not ready
			logutil.Info("retry.wait.hakeeper.running")
			launchSleep(time.Second)
			continue
		}
		return err
	}
}

func waitAnyShardReady(client logservice.CNHAKeeperClient) error {
	ctx, cancel := context.WithTimeoutCause(context.TODO(), time.Second*30, moerr.CauseWaitAnyShardReady)
	defer cancel()

	// wait shard ready
	for {
		if ok, err := func() (bool, error) {
			details, err := client.GetClusterDetails(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					err = moerr.AttachCause(ctx, err)
					logutil.Error("wait.tn.ready.timeout", zap.Error(err))
					return false, err
				}
				logutil.Error("wait.tn.ready.failed", zap.Error(err))
				return false, nil
			}
			for _, store := range details.TNStores {
				if len(store.Shards) > 0 {
					return true, nil
				}
			}
			logutil.Info("wait.tn.ready.not.ready")
			return false, nil
		}(); err != nil {
			return err
		} else if ok {
			logutil.Info("wait.tn.ready.ready.completed")
			return nil
		}
		launchSleep(time.Second)
	}
}

func waitClusterCondition(
	service string,
	cfg logservice.HAKeeperClientConfig,
	waitFunc func(logservice.CNHAKeeperClient) error,
) error {
	client, err := waitHAKeeperReady(service, cfg)
	if err != nil {
		return err
	}
	if err := waitFunc(client); err != nil {
		return err
	}
	if err := client.Close(); err != nil {
		logutil.Error("wait.cluster.condition.close.hakeeper.client.failed", zap.Error(err))
	}
	return nil
}
