/*
Copyright (C) 2023-2026 xingguangcuican6666

This file is part of new-api, which is licensed under the GNU Affero General
Public License v3.0. Original project: https://github.com/QuantumNous/new-api

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const (
	channelRatioProbeTaskDefaultIntervalMinutes = 15
	channelRatioProbeTaskBatchSize              = 100
	channelRatioProbeRequestTimeout             = 10 * time.Second
	channelRatioProbeMaxResponseBytes           = 1 << 20 // 1MB
	channelRatioProbeKeyConcurrency             = 4
	channelRatioProbeMaxKeysPerChannel          = 500

	// ratioProbeDisableReasonPrefix marks channel and key disables owned by this
	// probe. Only disables carrying this marker are re-enabled later, so a
	// compliant ratio never resurrects a channel that the relay or an admin
	// disabled for an unrelated reason.
	ratioProbeDisableReasonPrefix = "upstream ratio probe: "
)

// ratioProbeDecision is the verdict for one credential. A failed probe (network
// error, unusable response, missing group) leaves the channel/key state
// untouched so a flaky upstream cannot disable working traffic.
type ratioProbeDecision struct {
	key       string
	compliant bool
	failed    bool
	ratio     float64
	message   string
}

// channelRatioProbeRunner caches upstream documents for one task run. Multi-key
// channels usually point every key at the same upstream, and probes that do not
// send the channel API key return the same document for every key, so the cache
// collapses a whole channel into a single request in that case. Only the fetched
// document is shared; every channel still judges it against its own bounds.
type channelRatioProbeRunner struct {
	ctx   context.Context
	mu    sync.Mutex
	cache map[string]ratioProbeFetch
}

type ratioProbeFetch struct {
	ratios map[string]float64
	err    error
}

func newChannelRatioProbeRunner(ctx context.Context) *channelRatioProbeRunner {
	if ctx == nil {
		ctx = context.Background()
	}
	return &channelRatioProbeRunner{ctx: ctx, cache: make(map[string]ratioProbeFetch)}
}

func buildChannelRatioProbeURL(channel *model.Channel, config *dto.RatioProbeConfig) (string, error) {
	source := ""
	if config != nil {
		source = strings.ToLower(strings.TrimSpace(config.Source))
	}
	if source != "" && source != dto.RatioProbeSourceFollowAPI && source != dto.RatioProbeSourceCustom {
		return "", fmt.Errorf("invalid ratio probe source: %s", config.Source)
	}

	baseURL := config.NormalizedBaseURL()
	if source != dto.RatioProbeSourceCustom {
		baseURL = strings.TrimRight(strings.TrimSpace(channel.GetBaseURL()), "/")
	}
	if baseURL == "" {
		return "", errors.New("ratio probe base URL is empty")
	}
	if err := dto.ValidateRatioProbeBaseURL(baseURL); err != nil {
		return "", err
	}
	path := config.NormalizedPath()
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", errors.New("ratio probe path must be an absolute path starting with /")
	}
	if strings.ContainsAny(path, "?#") {
		return "", errors.New("ratio probe path must not contain query parameters or fragments")
	}
	return baseURL + path, nil
}

func describeRatioProbeRejection(config *dto.RatioProbeConfig, ratio float64) string {
	group := config.NormalizedGroup()
	if config.MaxGroupRatio != nil && ratio > *config.MaxGroupRatio {
		return fmt.Sprintf("group %s ratio %g exceeds max %g", group, ratio, *config.MaxGroupRatio)
	}
	if config.MinGroupRatio != nil && ratio < *config.MinGroupRatio {
		return fmt.Sprintf("group %s ratio %g is below min %g", group, ratio, *config.MinGroupRatio)
	}
	return fmt.Sprintf("group %s ratio %g is not accepted", group, ratio)
}

// probeKey fetches one upstream document and judges it. The Authorization header
// is either the probed key as a Bearer token or the configured header value, so a
// probe endpoint guarded by its own credential is reachable without exposing the
// channel key to it.
func (runner *channelRatioProbeRunner) probeKey(config *dto.RatioProbeConfig, requestURL string, proxy string, key string) ratioProbeDecision {
	authorization := ""
	if config.UsesAPIKey() {
		if credential := strings.TrimSpace(key); credential != "" {
			authorization = "Bearer " + credential
		}
	} else {
		authorization = config.NormalizedAuthorization()
	}
	cacheKey := strings.Join([]string{requestURL, authorization, proxy}, "\x00")

	runner.mu.Lock()
	fetch, hit := runner.cache[cacheKey]
	runner.mu.Unlock()
	if !hit {
		fetch.ratios, fetch.err = fetchUpstreamGroupRatios(runner.ctx, requestURL, authorization, proxy)
		runner.mu.Lock()
		runner.cache[cacheKey] = fetch
		runner.mu.Unlock()
	}

	decision := ratioProbeDecision{key: key}
	group := config.NormalizedGroup()
	ratio, found := fetch.ratios[group]
	switch {
	case fetch.err != nil:
		decision.failed = true
		decision.message = sanitizeFetchModelsError(fetch.err, key).Error()
	case !found:
		decision.failed = true
		decision.message = fmt.Sprintf("upstream group_ratio does not contain group %q", group)
	default:
		decision.ratio = ratio
		decision.compliant = config.Accepts(ratio)
		if !decision.compliant {
			decision.message = describeRatioProbeRejection(config, ratio)
		}
	}
	return decision
}

func fetchUpstreamGroupRatios(ctx context.Context, requestURL string, authorization string, proxy string) (map[string]float64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	requestCtx, cancel := context.WithTimeout(ctx, channelRatioProbeRequestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	client, err := service.GetHttpClientWithProxy(proxy)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, channelRatioProbeMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > channelRatioProbeMaxResponseBytes {
		return nil, fmt.Errorf("ratio config response exceeds %d bytes", channelRatioProbeMaxResponseBytes)
	}
	return parseUpstreamGroupRatios(body)
}

type channelRatioProbeTestResult struct {
	KeyIndex *int     `json:"key_index,omitempty"`
	Status   string   `json:"status"`
	Ratio    *float64 `json:"ratio,omitempty"`
	Message  string   `json:"message,omitempty"`
}

type channelRatioProbeTestData struct {
	Group      string                        `json:"group"`
	Configured bool                          `json:"configured"`
	Results    []channelRatioProbeTestResult `json:"results"`
}

func buildChannelRatioProbeTestResults(channel *model.Channel, config *dto.RatioProbeConfig, decisions []ratioProbeDecision) []channelRatioProbeTestResult {
	keyIndexes := make(map[string]int)
	if channel.ChannelInfo.IsMultiKey {
		for index, key := range channel.GetKeys() {
			keyIndexes[strings.TrimSpace(key)] = index + 1
		}
	}

	results := make([]channelRatioProbeTestResult, 0, len(decisions))
	for _, decision := range decisions {
		status := dto.RatioProbeStatusError
		if !decision.failed {
			status = dto.RatioProbeStatusRejected
			if !config.IsEnabled() {
				status = dto.RatioProbeStatusUnconfigured
			} else if decision.compliant {
				status = dto.RatioProbeStatusCompliant
			}
		}

		result := channelRatioProbeTestResult{
			Status:  status,
			Message: decision.message,
		}
		if !decision.failed {
			ratio := decision.ratio
			result.Ratio = &ratio
		}
		if channel.ChannelInfo.IsMultiKey {
			if index, ok := keyIndexes[strings.TrimSpace(decision.key)]; ok {
				result.KeyIndex = &index
			}
		}
		results = append(results, result)
	}
	return results
}

// TestChannelRatioProbe performs a one-off, read-only ratio probe for the
// selected channel. Unlike the scheduled task, it never changes channel or key
// status and returns every credential result for multi-key channels.
func TestChannelRatioProbe(c *gin.Context) {
	channelID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiError(c, err)
		return
	}

	channel, err := model.CacheGetChannel(channelID)
	if err != nil {
		channel, err = model.GetChannelById(channelID, true)
		if err != nil {
			common.ApiError(c, err)
			return
		}
	}

	config := channel.GetOtherSettings().RatioProbe
	if err := config.Validate(); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}
	requestURL, err := buildChannelRatioProbeURL(channel, config)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	requestCtx := context.Background()
	if c.Request != nil {
		requestCtx = c.Request.Context()
	}
	runner := newChannelRatioProbeRunner(requestCtx)
	decisions := runner.collectChannelRatioProbeDecisions(channel, config, requestURL)
	if len(decisions) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "ratio probe produced no result",
		})
		return
	}

	results := buildChannelRatioProbeTestResults(channel, config, decisions)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": channelRatioProbeTestData{
			Group:      config.NormalizedGroup(),
			Configured: config.IsEnabled(),
			Results:    results,
		},
	})
}

// parseUpstreamGroupRatios reads the group ratio table out of an upstream
// response. It accepts the New API management envelope
// ({"success":true,"data":{"group_ratio":{...}}}) as well as a bare
// {"group_ratio":{...}} document, so a static mirror of the endpoint works too.
func parseUpstreamGroupRatios(body []byte) (map[string]float64, error) {
	var envelope struct {
		Success    *bool           `json:"success"`
		Message    string          `json:"message"`
		Data       json.RawMessage `json:"data"`
		GroupRatio json.RawMessage `json:"group_ratio"`
	}
	if err := common.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid ratio config response: %w", err)
	}
	if envelope.Success != nil && !*envelope.Success {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = "upstream reported failure"
		}
		return nil, errors.New(message)
	}

	rawRatios := envelope.GroupRatio
	if len(envelope.Data) > 0 && common.GetJsonType(envelope.Data) == "object" {
		var data struct {
			GroupRatio json.RawMessage `json:"group_ratio"`
		}
		if err := common.Unmarshal(envelope.Data, &data); err != nil {
			return nil, fmt.Errorf("invalid ratio config response: %w", err)
		}
		if len(data.GroupRatio) > 0 {
			rawRatios = data.GroupRatio
		}
	}
	if len(rawRatios) == 0 || common.GetJsonType(rawRatios) != "object" {
		return nil, errors.New("upstream response does not expose group_ratio")
	}

	var entries map[string]json.RawMessage
	if err := common.Unmarshal(rawRatios, &entries); err != nil {
		return nil, fmt.Errorf("invalid group_ratio: %w", err)
	}
	ratios := make(map[string]float64, len(entries))
	for group, raw := range entries {
		if common.GetJsonType(raw) != "number" {
			continue
		}
		var ratio float64
		if err := common.Unmarshal(raw, &ratio); err != nil {
			continue
		}
		// A negative or non-finite group ratio is not a price; dropping it keeps
		// it out of the comparison instead of letting it satisfy a max bound.
		if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 {
			continue
		}
		ratios[group] = ratio
	}
	if len(ratios) == 0 {
		return nil, errors.New("upstream group_ratio has no usable entries")
	}
	return ratios, nil
}

// collectChannelRatioProbeDecisions probes every distinct credential of a
// channel in key order. Single-key channels contribute exactly one decision
// keyed by the whole key string, matching how the channel stores its credential.
func (runner *channelRatioProbeRunner) collectChannelRatioProbeDecisions(channel *model.Channel, config *dto.RatioProbeConfig, requestURL string) []ratioProbeDecision {
	proxy := channel.GetSetting().Proxy
	if !channel.ChannelInfo.IsMultiKey {
		return []ratioProbeDecision{runner.probeKey(config, requestURL, proxy, channel.Key)}
	}

	keys := channel.GetKeys()
	if len(keys) > channelRatioProbeMaxKeysPerChannel {
		common.SysLog(fmt.Sprintf(
			"ratio probe: channel_id=%d has %d keys, probing the first %d only",
			channel.Id, len(keys), channelRatioProbeMaxKeysPerChannel,
		))
		keys = keys[:channelRatioProbeMaxKeysPerChannel]
	}

	pending := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		pending = append(pending, key)
	}

	decisions := make([]ratioProbeDecision, len(pending))
	semaphore := make(chan struct{}, channelRatioProbeKeyConcurrency)
	launched := 0
	var waitGroup sync.WaitGroup
	for index, key := range pending {
		if runner.ctx.Err() != nil {
			break
		}
		waitGroup.Add(1)
		semaphore <- struct{}{}
		launched++
		go func(index int, key string) {
			defer waitGroup.Done()
			defer func() {
				<-semaphore
				if recovered := recover(); recovered != nil {
					common.SysLog(fmt.Sprintf("ratio probe panic: channel_id=%d error=%v", channel.Id, recovered))
					decisions[index] = ratioProbeDecision{key: key, failed: true, message: "probe panicked"}
				}
			}()
			decisions[index] = runner.probeKey(config, requestURL, proxy, key)
		}(index, key)
	}
	waitGroup.Wait()

	// A cancelled run stops launching workers, so only the settled prefix is a
	// real verdict; the untouched tail must not look like a compliant one.
	return decisions[:launched]
}

// channelRatioProbeResult reports what one channel's probe changed.
type channelRatioProbeResult struct {
	status        string
	statusChanged bool
	enabled       bool
	disabled      bool
	enabledKeys   int
	disabledKeys  int
}

// summarizeRatioProbeDecisions folds per-key verdicts into the state stored on
// the channel. The reported ratio is the highest one observed across successful
// probes, because that is the value a max bound is judged against.
func summarizeRatioProbeDecisions(decisions []ratioProbeDecision) (string, string, *float64) {
	if len(decisions) == 0 {
		return dto.RatioProbeStatusError, "probe produced no result", nil
	}

	succeeded := 0
	rejected := 0
	highest := 0.0
	rejectionMessage := ""
	errorMessage := ""
	for _, decision := range decisions {
		if decision.failed {
			if errorMessage == "" {
				errorMessage = decision.message
			}
			continue
		}
		if succeeded == 0 || decision.ratio > highest {
			highest = decision.ratio
		}
		succeeded++
		if decision.compliant {
			continue
		}
		rejected++
		if rejectionMessage == "" {
			rejectionMessage = decision.message
		}
	}

	switch {
	case succeeded == 0:
		return dto.RatioProbeStatusError, errorMessage, nil
	case rejected > 0:
		return dto.RatioProbeStatusRejected, rejectionMessage, &highest
	default:
		return dto.RatioProbeStatusCompliant, "", &highest
	}
}

func ratioProbeOwnsDisable(reason string) bool {
	return strings.HasPrefix(reason, ratioProbeDisableReasonPrefix)
}

func setChannelRatioProbeStatusReason(channel *model.Channel, message string) {
	info := channel.GetOtherInfo()
	info["status_reason"] = ratioProbeDisableReasonPrefix + message
	info["status_time"] = common.GetTimestamp()
	channel.SetOtherInfo(info)
}

// applySingleKeyRatioProbeDecision judges the channel as a whole. Re-enabling is
// restricted to channels this probe disabled so a compliant ratio cannot undo a
// relay-side auto-disable such as an invalid credential.
func applySingleKeyRatioProbeDecision(channel *model.Channel, byKey map[string]ratioProbeDecision, result *channelRatioProbeResult) {
	decision, probed := byKey[channel.Key]
	if !probed || decision.failed {
		return
	}
	statusReason, _ := channel.GetOtherInfo()["status_reason"].(string)
	switch {
	case !decision.compliant && channel.Status == common.ChannelStatusEnabled:
		channel.Status = common.ChannelStatusAutoDisabled
		setChannelRatioProbeStatusReason(channel, decision.message)
		result.statusChanged = true
		result.disabled = true
	case decision.compliant && channel.Status == common.ChannelStatusAutoDisabled && ratioProbeOwnsDisable(statusReason):
		channel.Status = common.ChannelStatusEnabled
		setChannelRatioProbeStatusReason(channel, "compliant group ratio")
		result.statusChanged = true
		result.enabled = true
	}
}

func markMultiKeyRatioProbeDisabled(channel *model.Channel, keyIndex int, message string) {
	if channel.ChannelInfo.MultiKeyDisabledReason == nil {
		channel.ChannelInfo.MultiKeyDisabledReason = make(map[int]string)
	}
	if channel.ChannelInfo.MultiKeyDisabledTime == nil {
		channel.ChannelInfo.MultiKeyDisabledTime = make(map[int]int64)
	}
	channel.ChannelInfo.MultiKeyDisabledReason[keyIndex] = ratioProbeDisableReasonPrefix + message
	channel.ChannelInfo.MultiKeyDisabledTime[keyIndex] = common.GetTimestamp()
}

// applyMultiKeyRatioProbeDecisions disables every non-compliant key and restores
// the keys this probe disabled earlier, then derives the channel status from the
// remaining enabled keys. Keys an admin disabled manually are left alone.
func applyMultiKeyRatioProbeDecisions(channel *model.Channel, byKey map[string]ratioProbeDecision, result *channelRatioProbeResult) {
	keys := channel.GetKeys()
	if len(keys) == 0 {
		return
	}
	if channel.ChannelInfo.MultiKeyStatusList == nil {
		channel.ChannelInfo.MultiKeyStatusList = make(map[int]int)
	}
	statusList := channel.ChannelInfo.MultiKeyStatusList

	for keyIndex, key := range keys {
		decision, probed := byKey[key]
		if !probed || decision.failed {
			continue
		}
		currentStatus, tracked := statusList[keyIndex]
		if !tracked {
			currentStatus = common.ChannelStatusEnabled
		}
		if !decision.compliant {
			if currentStatus != common.ChannelStatusEnabled {
				continue
			}
			statusList[keyIndex] = common.ChannelStatusAutoDisabled
			markMultiKeyRatioProbeDisabled(channel, keyIndex, decision.message)
			result.disabledKeys++
			continue
		}
		if currentStatus != common.ChannelStatusAutoDisabled ||
			!ratioProbeOwnsDisable(channel.ChannelInfo.MultiKeyDisabledReason[keyIndex]) {
			continue
		}
		delete(statusList, keyIndex)
		delete(channel.ChannelInfo.MultiKeyDisabledReason, keyIndex)
		delete(channel.ChannelInfo.MultiKeyDisabledTime, keyIndex)
		result.enabledKeys++
	}

	hasEnabledKey := false
	for keyIndex := range keys {
		if status, tracked := statusList[keyIndex]; !tracked || status == common.ChannelStatusEnabled {
			hasEnabledKey = true
			break
		}
	}
	switch {
	case !hasEnabledKey && channel.Status == common.ChannelStatusEnabled:
		channel.Status = common.ChannelStatusAutoDisabled
		setChannelRatioProbeStatusReason(channel, "all keys disabled")
		result.statusChanged = true
		result.disabled = true
	case hasEnabledKey && channel.Status == common.ChannelStatusAutoDisabled && result.enabledKeys > 0:
		// The channel-level status of a multi-key channel is derived from its
		// keys, so restoring a key also clears a stale all-keys-disabled state.
		channel.Status = common.ChannelStatusEnabled
		setChannelRatioProbeStatusReason(channel, "compliant group ratio")
		result.statusChanged = true
		result.enabled = true
	}
}

// applyChannelRatioProbe persists one channel's verdicts. The channel is re-read
// under the per-channel polling lock, the same lock the relay holds while it
// rotates keys, so neither writer saves a stale channel_info snapshot over the
// other.
func applyChannelRatioProbe(channelID int, decisions []ratioProbeDecision) (channelRatioProbeResult, error) {
	result := channelRatioProbeResult{}

	lock := model.GetChannelPollingLock(channelID)
	lock.Lock()
	defer lock.Unlock()

	channel, err := model.GetChannelById(channelID, true)
	if err != nil {
		return result, err
	}
	settings := channel.GetOtherSettings()
	if !settings.RatioProbe.IsEnabled() {
		// The switch was turned off while this run was in flight.
		return result, nil
	}
	if channel.Status == common.ChannelStatusManuallyDisabled {
		return result, nil
	}

	status, message, ratio := summarizeRatioProbeDecisions(decisions)
	result.status = status

	byKey := make(map[string]ratioProbeDecision, len(decisions))
	for _, decision := range decisions {
		byKey[decision.key] = decision
	}
	if channel.ChannelInfo.IsMultiKey {
		applyMultiKeyRatioProbeDecisions(channel, byKey, &result)
	} else {
		applySingleKeyRatioProbeDecision(channel, byKey, &result)
	}

	settings.RatioProbe.LastProbeTime = common.GetTimestamp()
	settings.RatioProbe.LastStatus = status
	settings.RatioProbe.LastMessage = message
	settings.RatioProbe.LastGroupRatio = ratio
	settings.RatioProbe.LastEnabledKeys = result.enabledKeys
	settings.RatioProbe.LastDisabledKeys = result.disabledKeys
	channel.SetOtherSettings(settings)

	updates := map[string]any{
		"settings":   channel.OtherSettings,
		"status":     channel.Status,
		"other_info": channel.OtherInfo,
	}
	if channel.ChannelInfo.IsMultiKey {
		updates["channel_info"] = channel.ChannelInfo
	}
	if err := model.DB.Model(&model.Channel{}).Where("id = ?", channel.Id).Updates(updates).Error; err != nil {
		return result, err
	}
	if result.statusChanged {
		if err := model.UpdateAbilityStatus(channel.Id, channel.Status == common.ChannelStatusEnabled); err != nil {
			common.SysLog(fmt.Sprintf("ratio probe: failed to update ability status: channel_id=%d error=%v", channel.Id, err))
		}
	}
	return result, nil
}

// probeChannelRatio probes one channel and persists the outcome. Configuration
// and URL failures are recorded as probe errors rather than skipped, so the
// channel editor can show why nothing is happening.
func (runner *channelRatioProbeRunner) probeChannelRatio(channel *model.Channel, config *dto.RatioProbeConfig) (channelRatioProbeResult, error) {
	if err := config.Validate(); err != nil {
		return applyChannelRatioProbe(channel.Id, []ratioProbeDecision{{key: channel.Key, failed: true, message: err.Error()}})
	}
	requestURL, err := buildChannelRatioProbeURL(channel, config)
	if err != nil {
		return applyChannelRatioProbe(channel.Id, []ratioProbeDecision{{key: channel.Key, failed: true, message: err.Error()}})
	}

	decisions := runner.collectChannelRatioProbeDecisions(channel, config, requestURL)
	if len(decisions) == 0 {
		// The run was cancelled before any credential was probed.
		return channelRatioProbeResult{}, nil
	}
	return applyChannelRatioProbe(channel.Id, decisions)
}

type channelRatioProbeSummary struct {
	CheckedChannels   int `json:"checked_channels"`
	CompliantChannels int `json:"compliant_channels"`
	RejectedChannels  int `json:"rejected_channels"`
	FailedChannels    int `json:"failed_channels"`
	DisabledChannels  int `json:"disabled_channels"`
	EnabledChannels   int `json:"enabled_channels"`
	DisabledKeys      int `json:"disabled_keys"`
	EnabledKeys       int `json:"enabled_keys"`
}

// runChannelRatioProbeTaskOnce runs one upstream group ratio probe cycle over
// every channel that enabled the probe and returns a summary for system task
// history. Manually disabled channels are skipped so the probe never fights an
// admin decision. ctx cancellation is honored between channels and batches so a
// runner that loses its lease stops promptly.
func runChannelRatioProbeTaskOnce(ctx context.Context, report func(processed, total int)) channelRatioProbeSummary {
	summary := channelRatioProbeSummary{}
	runner := newChannelRatioProbeRunner(ctx)
	probeStatuses := []int{common.ChannelStatusEnabled, common.ChannelStatusAutoDisabled}

	var totalChannels int64
	if err := model.DB.Model(&model.Channel{}).Where("status IN ?", probeStatuses).Count(&totalChannels).Error; err != nil {
		totalChannels = 0
	}
	processed := 0
	changed := false

	lastID := 0
scanLoop:
	for {
		if runner.ctx.Err() != nil {
			break
		}
		var channels []*model.Channel
		query := model.DB.
			Where("status IN ?", probeStatuses).
			Order("id asc").
			Limit(channelRatioProbeTaskBatchSize)
		if lastID > 0 {
			query = query.Where("id > ?", lastID)
		}
		if err := query.Find(&channels).Error; err != nil {
			common.SysLog(fmt.Sprintf("ratio probe task query failed: %v", err))
			break
		}
		if len(channels) == 0 {
			break
		}
		lastID = channels[len(channels)-1].Id

		for _, channel := range channels {
			if channel == nil {
				continue
			}
			if runner.ctx.Err() != nil {
				break scanLoop
			}

			processed++
			if report != nil {
				report(processed, int(totalChannels))
			}

			config := channel.GetOtherSettings().RatioProbe
			if !config.IsEnabled() {
				continue
			}

			summary.CheckedChannels++
			result, err := runner.probeChannelRatio(channel, config)
			if err != nil {
				summary.FailedChannels++
				common.SysLog(fmt.Sprintf("ratio probe failed: channel_id=%d channel_name=%s error=%v", channel.Id, channel.Name, err))
				continue
			}
			switch result.status {
			case dto.RatioProbeStatusCompliant:
				summary.CompliantChannels++
			case dto.RatioProbeStatusRejected:
				summary.RejectedChannels++
			case dto.RatioProbeStatusError:
				summary.FailedChannels++
			}
			summary.DisabledKeys += result.disabledKeys
			summary.EnabledKeys += result.enabledKeys
			if result.disabled {
				summary.DisabledChannels++
			}
			if result.enabled {
				summary.EnabledChannels++
			}
			if result.statusChanged || result.disabledKeys > 0 || result.enabledKeys > 0 {
				changed = true
			}

			if common.RequestInterval > 0 {
				select {
				case <-runner.ctx.Done():
					break scanLoop
				case <-time.After(common.RequestInterval):
				}
			}
		}

		if len(channels) < channelRatioProbeTaskBatchSize {
			break
		}
	}

	if report != nil && runner.ctx.Err() == nil {
		report(int(totalChannels), int(totalChannels))
	}
	if changed {
		refreshChannelRuntimeCache()
	}
	if summary.CheckedChannels > 0 || common.DebugEnabled {
		common.SysLog(fmt.Sprintf(
			"ratio probe task done: checked_channels=%d compliant=%d rejected=%d failed=%d disabled_channels=%d enabled_channels=%d disabled_keys=%d enabled_keys=%d",
			summary.CheckedChannels,
			summary.CompliantChannels,
			summary.RejectedChannels,
			summary.FailedChannels,
			summary.DisabledChannels,
			summary.EnabledChannels,
			summary.DisabledKeys,
			summary.EnabledKeys,
		))
	}
	return summary
}
