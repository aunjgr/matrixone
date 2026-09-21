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
	"time"

	"go.uber.org/zap"
)

func (s *service) startSiriusTopologyMonitor() error {
	capability := s.options.siriusCapability
	if capability == nil {
		return nil
	}
	validator := s.options.siriusTopologyValidator
	if validator == nil || s._hakeeperClient == nil {
		s.revokeSiriusTopology()
		s.closeSiriusTopologyHandoff()
		return siriusInternalErrorf("substrait: local Sirius runtime has no authoritative topology monitor")
	}
	if err := s.checkSiriusTopology(context.Background()); err != nil {
		s.closeSiriusTopologyHandoff()
		return err
	}
	err := s.stopper.RunNamedTask("sirius-topology-fence", func(ctx context.Context) {
		ticker := time.NewTicker(DefaultSiriusTopologyCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.checkSiriusTopology(ctx); err != nil {
					s.logger.Error("Sirius topology fence revoked", zap.Error(err))
					return
				}
			}
		}
	})
	if err != nil {
		s.revokeSiriusTopology()
		s.closeSiriusTopologyHandoff()
		return err
	}
	s.closeSiriusTopologyHandoff()
	return nil
}

func (s *service) checkSiriusTopology(parent context.Context) error {
	if s == nil || s.options.siriusCapability == nil ||
		s.options.siriusTopologyValidator == nil || s._hakeeperClient == nil {
		if s != nil {
			s.revokeSiriusTopology()
		}
		return siriusInternalErrorf("substrait: local Sirius topology fence is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, DefaultSiriusTopologyCheckInterval)
	defer cancel()
	if err := s.options.siriusTopologyValidator(ctx, s._hakeeperClient); err != nil {
		s.revokeSiriusTopology()
		return err
	}
	if err := s.options.siriusCapability.RenewTopology(DefaultSiriusTopologyValidity); err != nil {
		s.revokeSiriusTopology()
		return err
	}
	return nil
}

func (s *service) revokeSiriusTopology() {
	if s == nil {
		return
	}
	if s.options.siriusCapability != nil {
		s.options.siriusCapability.RevokeTopology()
	}
	if s.siriusRuntime != nil {
		s.siriusRuntime.RevokeLeaseCapability()
	}
}

func (s *service) closeSiriusTopologyHandoff() {
	if s == nil || s.options.siriusTopologyHandoff == nil {
		return
	}
	s.options.siriusTopologyHandoff.Stop()
	s.options.siriusTopologyHandoff = nil
}
