// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/newrelic/infrastructure-agent/internal/agent"
	"github.com/newrelic/infrastructure-agent/pkg/config"
	"github.com/newrelic/infrastructure-agent/pkg/metrics"
	"github.com/newrelic/infrastructure-agent/pkg/metrics/sampler"
	"github.com/newrelic/infrastructure-agent/pkg/metrics/types"
	"github.com/newrelic/infrastructure-agent/pkg/sample"
)

// processSampler is an implementation of the metrics_sender.Sampler interface, which returns runtime information about
// the currently running processes
type processSampler struct {
	harvest           Harvester
	containerSamplers []metrics.ContainerSampler
	lastRun           time.Time
	hasAlreadyRun     bool
	interval          time.Duration
	cache             *cache
}

var (
	_                       sampler.Sampler = (*processSampler)(nil) // static interface assertion
	containerNotRunningErrs                 = map[string]struct{}{}
	containerSamplerGetter                  = metrics.GetContainerSamplers //nolint:gochecknoglobals
)

// NewProcessSampler creates and returns a new process Sampler, given an agent context.
func NewProcessSampler(ctx agent.AgentContext) sampler.Sampler {
	hasConfig := ctx != nil && ctx.Config() != nil

	ttlSecs := config.DefaultContainerCacheMetadataLimit
	apiVersion := ""
	dockerContainerdNamespace := ""
	interval := config.FREQ_INTERVAL_FLOOR_PROCESS_METRICS
	var containerSamplers []metrics.ContainerSampler
	if hasConfig {
		cfg := ctx.Config()
		ttlSecs = cfg.ContainerMetadataCacheLimit
		apiVersion = cfg.DockerApiVersion
		dockerContainerdNamespace = cfg.DockerContainerdNamespace
		interval = cfg.MetricsProcessSampleRate
	}

	if (hasConfig && ctx.Config().ProcessContainerDecoration) || !hasConfig {
		containerSamplers = containerSamplerGetter(time.Duration(ttlSecs)*time.Second, apiVersion, dockerContainerdNamespace)
	}

	cache := newCache()
	harvest := newHarvester(ctx, &cache)

	return &processSampler{
		harvest:           harvest,
		containerSamplers: containerSamplers,
		cache:             &cache,
		interval:          time.Second * time.Duration(interval),
	}
}

func (ps *processSampler) OnStartup() {}

func (ps *processSampler) Name() string {
	return "ProcessSampler"
}

func (ps *processSampler) Interval() time.Duration {
	return ps.interval
}

func (ps *processSampler) Disabled() bool {
	return ps.Interval() <= config.FREQ_DISABLE_SAMPLING
}

// Sample returns samples for all the running processes, decorated with Docker runtime information, if applies.
func (ps *processSampler) Sample() (results sample.EventBatch, err error) {
	const topN = 10 // Limit to top 10 processes
	const CPUPercent =     0.5           // 0.5% CPU usage
	const MemoryRSSBytes =  5 * 1024 * 1024 // 5MB of RAM
	const IOReadBytes =    100 * 1024      // 100KB read
	const IOWriteBytes =   100 * 1024      // 100KB write
	// Use default thresholds
	// thresholds := DefaultThresholds

	var elapsedMs int64
	var elapsedSeconds float64
	now := time.Now()
	if ps.hasAlreadyRun {
		elapsedMs = (now.UnixNano() - ps.lastRun.UnixNano()) / 1000000
		elapsedSeconds = float64(elapsedMs) / 1000
	}
	ps.lastRun = now

	pids, err := ps.harvest.Pids()
	if err != nil {
		return nil, err
	}

	var containerDecorators []metrics.ProcessDecorator
	for _, containerSampler := range ps.containerSamplers {
		if !containerSampler.Enabled() {
			continue
		}

		decorator, err := containerSampler.NewDecorator()
		if err != nil {
			if id := containerIDFromNotRunningErr(err); id != "" {
				if _, ok := containerNotRunningErrs[id]; !ok {
					containerNotRunningErrs[id] = struct{}{}
					mplog.WithError(err).Warn("instantiating container sampler process decorator")
				}
			} else {
				mplog.WithError(err).Warn("instantiating container sampler process decorator")
				if strings.Contains(err.Error(), "client is newer than server") {
					mplog.WithError(err).Error("Only docker api version from 1.24 upwards are officially supported. You can still use the docker_api_version configuration to work with older versions. You can check https://docs.docker.com/develop/sdk/ what api version maps with each docker version.")
				}
			}
		} else {
			containerDecorators = append(containerDecorators, decorator)
		}
	}

	var processSamples []*types.ProcessSample
	for _, pid := range pids {
		processSample, err := ps.harvest.Do(pid, elapsedSeconds)
		if err != nil {
			procLog := mplog.WithError(err)
			if errors.Is(err, errProcessWithoutRSS) {
				procLog = procLog.WithField(config.TracesFieldName, config.ProcessTrace)
			}

			procLog.WithField("pid", pid).Debug("Skipping process.")
			continue
		}

		for _, containerDecorator := range containerDecorators {
			if containerDecorator != nil {
				containerDecorator.Decorate(processSample)
			}
		}

		processSamples = append(processSamples, processSample)

		// Apply threshold filtering - only include processes that meet at least one threshold criteria
		meetsIOReadThreshold := false
		meetsIOWriteThreshold := false

		if processSample.IOTotalReadBytes != nil {
			meetsIOReadThreshold = *processSample.IOTotalReadBytes >= IOReadBytes
		}

		if processSample.IOTotalWriteBytes != nil {
			meetsIOWriteThreshold = *processSample.IOTotalWriteBytes >= IOWriteBytes
		}

		if processSample.CPUPercent >= CPUPercent ||
			processSample.MemoryRSSBytes >= MemoryRSSBytes ||
			meetsIOReadThreshold || meetsIOWriteThreshold {
			processSamples = append(processSamples, processSample)
		}
	}

	// Sort processes based on multiple resource criteria (CPU, Memory, Network)
	sort.Slice(processSamples, func(i, j int) bool {
		// Primary sort by CPU usage
		if processSamples[i].CPUPercent != processSamples[j].CPUPercent {
			return processSamples[i].CPUPercent > processSamples[j].CPUPercent
		}
		// Secondary sort by memory usage
		if processSamples[i].MemoryRSSBytes != processSamples[j].MemoryRSSBytes {
			return processSamples[i].MemoryRSSBytes > processSamples[j].MemoryRSSBytes
		}
		// Tertiary sort by IO operations (as a proxy for network activity)
		var totalIOi, totalIOj uint64

		if processSamples[i].IOTotalReadBytes != nil {
			totalIOi += *processSamples[i].IOTotalReadBytes
		}
		if processSamples[i].IOTotalWriteBytes != nil {
			totalIOi += *processSamples[i].IOTotalWriteBytes
		}

		if processSamples[j].IOTotalReadBytes != nil {
			totalIOj += *processSamples[j].IOTotalReadBytes
		}
		if processSamples[j].IOTotalWriteBytes != nil {
			totalIOj += *processSamples[j].IOTotalWriteBytes
		}

		return totalIOi > totalIOj
	})

	// Limit to top N processes
	if len(processSamples) > topN {
		processSamples = processSamples[:topN]
	}

	for _, sample := range processSamples {
		results = append(results, ps.normalizeSample(sample))
	}

	ps.cache.items.RemoveUntilLen(len(pids))
	ps.hasAlreadyRun = true
	return results, nil
}

func (ps *processSampler) normalizeSample(s *types.ProcessSample) sample.Event {
	if len(s.ContainerLabels) > 0 {
		sb, err := json.Marshal(s)
		if err == nil {
			bm := &types.FlatProcessSample{}
			if err = json.Unmarshal(sb, bm); err == nil {
				for name, value := range s.ContainerLabels {
					key := fmt.Sprintf("containerLabel_%s", name)
					(*bm)[key] = value
				}
				return bm
			}
		} else {
			mplog.WithError(err).WithField("sample", fmt.Sprintf("%+v", s)).Debug("normalizeSample can't operate on the sample.")
		}
	}
	return s
}

func containerIDFromNotRunningErr(err error) string {
	prefix := "Error response from daemon: Container "
	suffix := " is not running"
	msg := err.Error()
	i := strings.Index(msg, prefix)
	j := strings.Index(msg, suffix)
	if i == -1 || j == -1 {
		return ""
	}
	return msg[len(prefix):j]
}
