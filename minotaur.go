// Minotaur the twin Credential Tester by @mekalabs.
// This tool was created to solve specific problems, about fundamental things that are often overlooked in credential testing problems.
// The principle of this tool is no one credentials left behind.
// Authorized only, great power come great responsibility.
// Battle tested with 32 million tasks, maximum RAM usage of 8GB, use --script for optimalization.
// Smart blacklist need load all task for acuracy
// Use the RAM limit function to avoid chaos in the martial arts world.
// Required proto.go to run this tool.
// ===================================
// {{{ IMPORT
package main
import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os/exec"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)
// }}}
// {{{ SECTION 1: CORE TYPES
type ProtocolConfig struct {
	Name    string
	Port    int
	Enabled bool
}

type Config struct {
	TargetsFile        string
	UsersFile          string
	PasswordsFile      string
	OutputFile         string
	MaxThreads         int
	MaxPerHost         int
	BaseDelay          float64
	RetryDelay         float64
	MaxRetries         int
	MaxConsecutiveFN   int
	MaxTotalFN         int
	ExponentialBackoff bool
	Timeout            float64
	Debug              bool
	NoResume           bool
	ForceResume        bool
	Protocols          []ProtocolConfig
	RAMLimitBytes      int64
	Command            string
	Mute               bool
}

type Task struct {
	Target   string
	Username string
	Password string
	Protocol string
	Port     int
	ID       string
}

type Result struct {
	Timestamp      string
	Target         string
	Username       string
	Password       string
	Protocol       string
	Port           int
	Status         string
	Latency        float64
	Error          string
	CommandOutput  string
}
// }}}
// {{{ SECTION 2: FORMATTING UTILITIES
func formatNumberWithCommas(n int64) string {
	if n < 0 {
		return "-" + formatNumberWithCommas(-n)
	}
	if n < 1000 {
		return strconv.FormatInt(n, 10)
	}
	str := strconv.FormatInt(n, 10)
	var result strings.Builder
	length := len(str)

	for i, char := range str {
		result.WriteRune(char)
		if (length-i-1)%3 == 0 && i != length-1 {
			result.WriteByte(',')
		}
	}
	return result.String()
}

func parseRAMLimit(limit string) (int64, error) {
	limit = strings.ToUpper(strings.TrimSpace(limit))

	if limit == "0" || limit == "UNLIMITED" || limit == "" {
		return 0, nil
	}
	if strings.HasPrefix(limit, "-") {
		return 0, fmt.Errorf("invalid RAM limit: negative value")
	}

	var multiplier float64 = 1
	var suffix string

	if strings.HasSuffix(limit, "GB") {
		multiplier = 1024 * 1024 * 1024
		suffix = "GB"
	} else if strings.HasSuffix(limit, "MB") {
		multiplier = 1024 * 1024
		suffix = "MB"
	} else if strings.HasSuffix(limit, "KB") {
		multiplier = 1024
		suffix = "KB"
	} else {
		val, err := strconv.ParseInt(limit, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid RAM limit format: %s", limit)
		}
		return val, nil
	}

	numStr := strings.TrimSuffix(limit, suffix)
	numStr = strings.TrimSpace(numStr)

	value, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in RAM limit: %s", limit)
	}

	return int64(value * multiplier), nil
}

func formatBytes(bytes int64) string {
	if bytes <= 0 {
		return "Unlimited"
	}
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

func averageStringLength(strs []string) int {
	if len(strs) == 0 {
		return 0
	}
	total := 0
	for _, s := range strs {
		total += len(s)
	}
	return total / len(strs)
}

func formatDuration(seconds float64) string {
	if seconds < 0 {
		return "0s"
	}

	hours := int(seconds) / 3600
	minutes := (int(seconds) % 3600) / 60
	secs := int(seconds) % 60

	if hours > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, secs)
	}
	return fmt.Sprintf("%02d:%02d", minutes, secs)
}
// }}}
// {{{ SECTION 3: FILE UTILITIES
func CreateTempFileWithContent(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "minotaur-*.txt")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content + "\n"); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func CreateTempFileWithLines(lines []string) (string, error) {
	tmpFile, err := os.CreateTemp("", "minotaur-*.txt")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	for _, line := range lines {
		if _, err := tmpFile.WriteString(line + "\n"); err != nil {
			os.Remove(tmpFile.Name())
			return "", err
		}
	}

	return tmpFile.Name(), nil
}

func loadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}


// }}}
// {{{ SECTION 4: COLOR WRAPPERS
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
)
func Cyan(text string) string { return ColorCyan + text + ColorReset }
func Green(text string) string { return ColorGreen + text + ColorReset }
func Magenta(text string) string { return ColorMagenta + text + ColorReset }
func BoldCyan(text string) string { return ColorBold + ColorCyan + text + ColorReset }
func HeaderPlus(text string) string {
	return ColorWhite + "[" + ColorCyan + "+" + ColorWhite + "] " + ColorCyan + text + ColorReset
}
func HeaderInfo(text string) string {
	return ColorWhite + "[" + ColorCyan + "i" + ColorWhite + "] " + ColorBold + ColorCyan + text + ColorReset
}
func HeaderWarning(text string) string {
	return ColorWhite + "[" + ColorCyan + "!" + ColorWhite + "] " + ColorBold + ColorCyan + text + ColorReset
}
func HeaderSuccess(text string) string {
	return ColorWhite + "[" + ColorCyan + "✓" + ColorWhite + "] " + ColorBold + ColorCyan + text + ColorReset
}
func TreeBranch() string { return ColorWhite + "  ├─" + ColorReset }
func TreeEnd() string    { return ColorWhite + "  └─" + ColorReset }
func TreeLine() string   { return ColorWhite + "  │  " + ColorReset }
func TreeSpace() string  { return "   " }

func FormatConfigNumber(num interface{}) string {
	var numStr string
	switch v := num.(type) {
	case int:
		numStr = strconv.Itoa(v)
	case int64:
		numStr = strconv.FormatInt(v, 10)
	case float64:
		numStr = strconv.FormatFloat(v, 'f', 1, 64)
	case string:
		numStr = v
	default:
		numStr = fmt.Sprintf("%v", v)
	}
	return ColorMagenta + numStr + ColorReset
}
// }}}
// {{{ SECTION 5: DEBUG WRAPPER
type DebugLogger struct {
	enabled bool
	prefix  string
}

func NewDebugLogger(enabled bool, prefix string) *DebugLogger {
	return &DebugLogger{
		enabled: enabled,
		prefix:  prefix,
	}
}

func (dl *DebugLogger) Log(format string, args ...interface{}) {
	if dl.enabled {
		message := fmt.Sprintf(format, args...)
		if dl.prefix != "" {
			fmt.Printf("[%s] %s\n", dl.prefix, message)
		} else {
			fmt.Printf("[DEBUG] %s\n", message)
		}
	}
}

func (dl *DebugLogger) LogSimple(message string) {
	if dl.enabled {
		if dl.prefix != "" {
			fmt.Printf("[%s] %s\n", dl.prefix, message)
		} else {
			fmt.Printf("[DEBUG] %s\n", message)
		}
	}
}

func debugLog(debug bool, prefix, format string, args ...interface{}) {
	if debug {
		if prefix != "" {
			fmt.Printf("[%s] ", prefix)
		} else {
			fmt.Printf("[DEBUG] ")
		}
		fmt.Printf(format+"\n", args...)
	}
}

func debugLogSimple(debug bool, prefix, message string) {
	if debug {
		if prefix != "" {
			fmt.Printf("[%s] %s\n", prefix, message)
		} else {
			fmt.Printf("[DEBUG] %s\n", message)
		}
	}
}
// }}}
// {{{ SECTION 6: PROGRESS BAR
type ProgressBar struct {
	totalTasks          int
	totalHosts          int
	tasksProcessed      int64
	hostsTested         int64
	successCount        int64
	blacklistCount      int64
	skipCount           int64
	startTime           time.Time
	mu                  sync.RWMutex
	spinnerChars        []string
	spinnerIndex        int
	debug               bool
	enabled             bool
	mute                bool
	lastUpdateTime      time.Time
	updateInterval      time.Duration
	completedHostsCount int
	successBuffer       []string
	successBufferLock   sync.Mutex

	currentBatch        int
	totalBatches        int
	batchStartTime      time.Time
	lastBatchStats      struct {
		hosts  int
		tasks  int
		time   float64
	}
}

func NewProgressBar(debug bool, mute bool) *ProgressBar {
	return &ProgressBar{
		spinnerChars:   []string{"-", "\\", "|", "/"},
		spinnerIndex:   0,
		debug:          debug,
		enabled:        true,
		mute:           mute,
		lastUpdateTime: time.Now(),
		updateInterval: 100 * time.Millisecond,
		startTime:      time.Now(),
		currentBatch:   1,
		totalBatches:   1,
		batchStartTime: time.Now(),
	}
}

func (pb *ProgressBar) Initialize(totalTasks, totalHosts, completedHosts, totalBatches int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.totalTasks = totalTasks
	pb.totalHosts = totalHosts
	pb.completedHostsCount = completedHosts
	pb.totalBatches = totalBatches
	pb.startTime = time.Now()
	pb.batchStartTime = time.Now()
	pb.tasksProcessed = 0
	pb.hostsTested = int64(completedHosts)
	pb.successCount = 0
	pb.blacklistCount = 0
	pb.skipCount = 0
	pb.successBuffer = nil
	pb.currentBatch = 1

	debugLog(pb.debug, "PROGRESS-BAR", "Initialized: %d tasks, %d hosts, %d batches",
		totalTasks, totalHosts, totalBatches)
}

func (pb *ProgressBar) SetCurrentBatch(batchIndex, totalBatches int) {
	pb.mu.Lock()
	pb.currentBatch = batchIndex
	pb.totalBatches = totalBatches
	pb.batchStartTime = time.Now()
	pb.mu.Unlock()

	debugLog(pb.debug, "BATCH", "Starting batch %d/%d", batchIndex, totalBatches)
}

func (pb *ProgressBar) AddBatchSkips(skipCount int) {
	if !pb.enabled {
		return
	}

	pb.mu.Lock()
	pb.skipCount += int64(skipCount)
	pb.mu.Unlock()
	pb.Update(false, false, false, false, false)
}

func (pb *ProgressBar) AddSuccessMessage(msg string) {
	if !pb.enabled {
		return
	}

	coloredMsg := ColorWhite + "[" + ColorMagenta + "+" + ColorWhite + "] " +
		ColorBold + ColorGreen + msg + ColorReset

	pb.successBufferLock.Lock()
	pb.successBuffer = append(pb.successBuffer, coloredMsg)
	pb.successBufferLock.Unlock()

	pb.mu.Lock()
	pb.lastUpdateTime = time.Time{}
	pb.mu.Unlock()

	pb.renderWithSuccess()
}

func (pb *ProgressBar) Update(taskProcessed bool, hostTested bool, success bool, blacklisted bool, skipped bool) {
	if !pb.enabled {
		return
	}

	pb.mu.Lock()
	if taskProcessed {
		pb.tasksProcessed++
	}
	if skipped {
		pb.skipCount++
	}
	if hostTested {
		pb.hostsTested++
	}
	if success {
		pb.successCount++
	}
	if blacklisted {
		pb.blacklistCount++
	}
	pb.mu.Unlock()

	now := time.Now()
	if now.Sub(pb.lastUpdateTime) < pb.updateInterval {
		return
	}

	pb.mu.Lock()
	pb.lastUpdateTime = now
	pb.mu.Unlock()

	pb.renderProgressOnly()
}

func (pb *ProgressBar) BatchCompleted(hosts, tasks int) {
	pb.mu.Lock()
	elapsed := time.Since(pb.batchStartTime).Seconds()
	pb.lastBatchStats.hosts = hosts
	pb.lastBatchStats.tasks = tasks
	pb.lastBatchStats.time = elapsed
	pb.mu.Unlock()

	fmt.Printf("\n%sCompleted in %.0fs | Hosts: %d | Tasks: %s\n",
		ColorWhite+"[Batch "+ColorMagenta+strconv.Itoa(pb.currentBatch)+
		ColorWhite+"/"+ColorMagenta+strconv.Itoa(pb.totalBatches)+ColorWhite+"] ",
		elapsed, hosts, formatNumberWithCommas(int64(tasks)))
}

func (pb *ProgressBar) renderWithSuccess() {
	if !pb.enabled || pb.totalTasks == 0 {
		return
	}

	pb.successBufferLock.Lock()
	successCount := len(pb.successBuffer)
	pb.successBufferLock.Unlock()

	if successCount > 0 && !pb.mute {
		pb.successBufferLock.Lock()
		fmt.Print("\r\033[K")

		for _, msg := range pb.successBuffer {
			fmt.Println(msg)
		}
		pb.successBuffer = nil
		pb.successBufferLock.Unlock()
	}

	pb.renderProgressOnly()
}

func (pb *ProgressBar) renderProgressOnly() {
	if !pb.enabled || pb.totalTasks == 0 {
		return
	}

	// Skip jika belum waktunya update (kecuali dipaksa)
	// now := time.Now()
	// if !pb.lastUpdateTime.IsZero() && now.Sub(pb.lastUpdateTime) < pb.updateInterval && !pb.debug {
	// return
	//}

	pb.mu.Lock()
	//pb.lastUpdateTime = now
	pb.mu.Unlock()

	pb.mu.RLock()
	totalProcessed := pb.tasksProcessed + pb.skipCount
	processed := float64(totalProcessed)
	total := float64(pb.totalTasks)

	if processed > total {
		processed = total
	}

	progress := processed / total
	progressPercent := progress * 100

	elapsed := time.Since(pb.startTime).Seconds()
	etFormatted := formatDuration(elapsed)

	var etaFormatted string
	if elapsed > 0 && processed > 0 {
		tasksPerSecond := processed / elapsed
		remainingTasks := total - processed

		if tasksPerSecond > 0 {
			etaSeconds := remainingTasks / tasksPerSecond
			etaFormatted = formatDuration(etaSeconds)
		} else {
			etaFormatted = "--:--"
		}
	} else {
		etaFormatted = "--:--"
	}

	pb.spinnerIndex = (pb.spinnerIndex + 1) % len(pb.spinnerChars)
	spinner := pb.spinnerChars[pb.spinnerIndex]

	progressStr := fmt.Sprintf("[%s] Hunting %.1f%% (%s/%s) | Batch: %d/%d | ET:%s ETA:%s | Success: %s | Blacklist: %s | Skip: %s ",
		spinner,
		progressPercent,
		FormatConfigNumber(totalProcessed),
		FormatConfigNumber(int64(pb.totalTasks)),
		pb.currentBatch, pb.totalBatches,
		Magenta(etFormatted),
		Magenta(etaFormatted),
		FormatConfigNumber(pb.successCount),
		FormatConfigNumber(pb.blacklistCount),
		FormatConfigNumber(pb.skipCount))

	pb.mu.RUnlock()

	fmt.Print("\r" + progressStr)
}

func (pb *ProgressBar) render() {
	pb.renderProgressOnly()
}

func (pb *ProgressBar) Finalize() {
	if !pb.enabled {
		return
	}

	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.successBufferLock.Lock()
	if len(pb.successBuffer) > 0 && !pb.mute {
		fmt.Print("\r\033[K")

		for _, msg := range pb.successBuffer {
			fmt.Println(msg)
		}
		pb.successBuffer = nil
	}
	pb.successBufferLock.Unlock()

	totalProcessed := pb.tasksProcessed + pb.skipCount
	if totalProcessed > int64(pb.totalTasks) {
		totalProcessed = int64(pb.totalTasks)
	}

	elapsed := time.Since(pb.startTime).Seconds()
	etFormatted := formatDuration(elapsed)

	finalStr := fmt.Sprintf("[✓] Hunting %.1f%% (%s/%s) | Batch: %d/%d | ET:%s ETA:%s | Success: %s | Blacklist: %s | Skip: %s \n",
		100.0,
		FormatConfigNumber(totalProcessed),
		FormatConfigNumber(int64(pb.totalTasks)),
		pb.currentBatch, pb.totalBatches,
		Magenta(etFormatted),
		Magenta("00:00"),
		FormatConfigNumber(pb.successCount),
		FormatConfigNumber(pb.blacklistCount),
		FormatConfigNumber(pb.skipCount))

	fmt.Print("\r" + finalStr)
	pb.enabled = false
}

func (pb *ProgressBar) Disable() {
	pb.enabled = false
	fmt.Printf("\r\033[K")
}

func (pb *ProgressBar) GetStats() map[string]interface{} {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	totalProcessed := pb.tasksProcessed + pb.skipCount
	if totalProcessed > int64(pb.totalTasks) {
		totalProcessed = int64(pb.totalTasks)
	}

	return map[string]interface{}{
		"total_tasks":     pb.totalTasks,
		"total_hosts":     pb.totalHosts,
		"tasks_processed": pb.tasksProcessed,
		"tasks_skipped":   pb.skipCount,
		"total_processed": totalProcessed,
		"hosts_tested":    pb.hostsTested,
		"success_count":   pb.successCount,
		"blacklist_count": pb.blacklistCount,
		"completed_hosts": pb.completedHostsCount,
		"current_batch":   pb.currentBatch,
		"total_batches":   pb.totalBatches,
	}
}
// }}}
// {{{ SECTION 7: PROGRESS MANAGER
type ProgressState struct {
	Version        string   `json:"version"`
	ConfigHash     string   `json:"config_hash"`
	CompletedHosts []string `json:"completed_hosts"`
	Timestamp      string   `json:"timestamp"`

	Stats struct {
		SuccessCount   int64 `json:"success_count"`
		BlacklistCount int64 `json:"blacklist_count"`
		SkipCount      int64 `json:"skip_count"`
		TasksProcessed int64 `json:"tasks_processed"`
		HostsTested    int64 `json:"hosts_tested"`
	} `json:"stats"`

	BlacklistedHosts []string `json:"blacklisted_hosts"`
	SuccessfulHosts  []string `json:"successful_hosts"`
}

type ProgressManager struct {
	state    ProgressState
	filePath string
	mu       sync.RWMutex
	debug    bool
}

func NewProgressManager(filePath string, debug bool) *ProgressManager {
	return &ProgressManager{
		filePath: filePath,
		debug:    debug,
		state: ProgressState{
			Version: "1.0",
		},
	}
}

func CalculateConfigHash(targetsFile, usersFile, passwordsFile string, protocols []ProtocolConfig) (string, error) {
	hash := md5.New()

	hashFile := func(filename string) error {
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		hash.Write(content)
		hash.Write([]byte{0})
		return nil
	}

	files := []string{targetsFile, usersFile, passwordsFile}
	for _, file := range files {
		if err := hashFile(file); err != nil {
			return "", fmt.Errorf("failed to hash %s: %v", file, err)
		}
	}

	for _, proto := range protocols {
		hash.Write([]byte(proto.Name))
		hash.Write([]byte(strconv.Itoa(proto.Port)))
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (pm *ProgressManager) Load(currentHash string) (bool, string, map[string]interface{}, []string, []string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, err := os.Stat(pm.filePath); os.IsNotExist(err) {
		debugLog(pm.debug, "PROGRESS", "No progress file found: %s", pm.filePath)
		return false, "no progress file", nil, nil, nil
	}

	data, err := os.ReadFile(pm.filePath)
	if err != nil {
		debugLog(pm.debug, "PROGRESS", "Failed to read progress file: %v", err)
		return false, fmt.Sprintf("read error: %v", err), nil, nil, nil
	}

	if err := json.Unmarshal(data, &pm.state); err != nil {
		debugLog(pm.debug, "PROGRESS", "Failed to parse progress file: %v", err)
		return false, fmt.Sprintf("parse error: %v", err), nil, nil, nil
	}

	if pm.state.Version != "1.0" {
		msg := fmt.Sprintf("unsupported version: %s (expected 1.0)", pm.state.Version)
		debugLog(pm.debug, "PROGRESS", "%s", msg)
		return false, msg, nil, nil, nil
	}

	if pm.state.ConfigHash != currentHash {
		msg := fmt.Sprintf("config hash mismatch: stored=%s, current=%s",
			pm.state.ConfigHash, currentHash)
		debugLog(pm.debug, "PROGRESS", "%s", msg)
		return false, msg, nil, nil, nil
	}

	stats := map[string]interface{}{
		"success_count":    pm.state.Stats.SuccessCount,
		"blacklist_count":  pm.state.Stats.BlacklistCount,
		"skip_count":       pm.state.Stats.SkipCount,
		"tasks_processed":  pm.state.Stats.TasksProcessed,
		"hosts_tested":     pm.state.Stats.HostsTested,
	}

	debugLog(pm.debug, "PROGRESS", "Loaded progress: %d completed hosts, success: %d, blacklist: %d, skip: %d",
		len(pm.state.CompletedHosts), pm.state.Stats.SuccessCount,
		pm.state.Stats.BlacklistCount, pm.state.Stats.SkipCount)

	return true, "loaded successfully", stats, pm.state.BlacklistedHosts, pm.state.SuccessfulHosts
}

func (pm *ProgressManager) Save(stats map[string]interface{}, blacklistedHosts, successfulHosts []string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.state.Timestamp = time.Now().Format(time.RFC3339)

	if stats != nil {
		if val, ok := stats["success_count"].(int64); ok {
			pm.state.Stats.SuccessCount = val
		}
		if val, ok := stats["blacklist_count"].(int64); ok {
			pm.state.Stats.BlacklistCount = val
		}
		if val, ok := stats["skip_count"].(int64); ok {
			pm.state.Stats.SkipCount = val
		}
		if val, ok := stats["tasks_processed"].(int64); ok {
			pm.state.Stats.TasksProcessed = val
		}
		if val, ok := stats["hosts_tested"].(int64); ok {
			pm.state.Stats.HostsTested = val
		}
	}

	pm.state.BlacklistedHosts = blacklistedHosts
	pm.state.SuccessfulHosts = successfulHosts

	data, err := json.MarshalIndent(pm.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal progress: %v", err)
	}

	tempFile := pm.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write progress: %v", err)
	}
	if err := os.Rename(tempFile, pm.filePath); err != nil {
		return fmt.Errorf("failed to rename progress file: %v", err)
	}

	debugLog(pm.debug, "PROGRESS", "Saved progress: %s (success: %d, blacklist: %d, skip: %d)",
		pm.filePath, pm.state.Stats.SuccessCount,
		pm.state.Stats.BlacklistCount, pm.state.Stats.SkipCount)
	return nil
}

func (pm *ProgressManager) AddCompletedHost(host string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, h := range pm.state.CompletedHosts {
		if h == host {
			return
		}
	}

	pm.state.CompletedHosts = append(pm.state.CompletedHosts, host)

	debugLog(pm.debug, "PROGRESS", "Added completed host: %s", host)
}

func (pm *ProgressManager) IsCompleted(host string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, h := range pm.state.CompletedHosts {
		if h == host {
			return true
		}
	}
	return false
}

func (pm *ProgressManager) GetCompletedStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return map[string]interface{}{
		"total_completed": len(pm.state.CompletedHosts),
		"completed_hosts": pm.state.CompletedHosts,
		"timestamp":       pm.state.Timestamp,
		"config_hash":     pm.state.ConfigHash,
	}
}

func (pm *ProgressManager) SetConfigHash(hash string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.state.ConfigHash = hash
}

func (pm *ProgressManager) Cleanup() error {
	if err := os.Remove(pm.filePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	debugLog(pm.debug, "PROGRESS", "Cleaned up progress file")
	return nil
}

func (pm *ProgressManager) GetCompletedHosts() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	hosts := make([]string, len(pm.state.CompletedHosts))
	copy(hosts, pm.state.CompletedHosts)
	return hosts
}

func (pm *ProgressManager) GetBlacklistedHosts() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.state.BlacklistedHosts
}

func (pm *ProgressManager) GetSuccessfulHosts() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.state.SuccessfulHosts
}
// }}}
// {{{ SECTION 8: SMART BLACKLIST
type SmartBlacklist struct {
	maxConsecutive int
	maxTotal       int
	debug          bool

	consecutiveCount sync.Map
	totalCount       sync.Map
	blacklistedHosts sync.Map
	successfulHosts  sync.Map

	stats struct {
	hostsBlacklisted    int64
	consecutiveTriggers int64
	totalTriggers       int64
	}
}

func NewSmartBlacklist(maxConsecutive, maxTotal int, debug bool) *SmartBlacklist {
	return &SmartBlacklist{
		maxConsecutive: maxConsecutive,
		maxTotal:       maxTotal,
		debug:          debug,
	}
}

func (b *SmartBlacklist) isRetryable(status string) bool {
	return IsRetryableStatus(status)
}

func (b *SmartBlacklist) isFalseNegative(status string) bool {
	if b.isAuthFailed(status) {
		return false
	}
	_, exists := allFalseNegatives[status]
	return exists
}

func (b *SmartBlacklist) isAuthFailed(status string) bool {
	return IsAuthFailedStatus(status)
}

func (b *SmartBlacklist) isSuccess(status string) bool {
	return IsSuccessStatus(status)
}

func (b *SmartBlacklist) ProcessResult(host, status string) (bool, string) {
	if _, ok := b.successfulHosts.Load(host); ok {
		debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, "host already successful")
		return false, "host already successful"
	}

	if _, ok := b.blacklistedHosts.Load(host); ok {
		debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, "host blacklisted")
		return true, "host blacklisted"
	}

	if b.isSuccess(status) {
		b.successfulHosts.Store(host, true)
		b.consecutiveCount.Store(host, 0)
		b.totalCount.Store(host, 0)
		debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, "success - host marked successful")
		return false, "success - host marked successful"
	}

	if b.isAuthFailed(status) {
		b.consecutiveCount.Store(host, 0)
		debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, "auth failure - reset consecutive counter")
		return false, "auth failure - reset consecutive counter"
	}

	if b.isFalseNegative(status) {
		var consecutive int
		if val, ok := b.consecutiveCount.Load(host); ok {
			consecutive = val.(int)
		}
		consecutive++
		b.consecutiveCount.Store(host, consecutive)

		var total int
		if val, ok := b.totalCount.Load(host); ok {
			total = val.(int)
		}
		total++
		b.totalCount.Store(host, total)

		if consecutive >= b.maxConsecutive {
			b.blacklistedHosts.Store(host, true)
			atomic.AddInt64(&b.stats.hostsBlacklisted, 1)
			atomic.AddInt64(&b.stats.consecutiveTriggers, 1)
			reason := fmt.Sprintf("%d consecutive false negatives", consecutive)
			debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, reason)
			return true, reason
		}

		if total >= b.maxTotal {
			b.blacklistedHosts.Store(host, true)
			atomic.AddInt64(&b.stats.hostsBlacklisted, 1)
			atomic.AddInt64(&b.stats.totalTriggers, 1)
			reason := fmt.Sprintf("%d total false negatives", total)
			debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, reason)
			return true, reason
		}

		reason := fmt.Sprintf("false negative (consecutive: %d, total: %d)", consecutive, total)
		debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, reason)
		return false, reason
	}

	b.consecutiveCount.Store(host, 0)
	reason := fmt.Sprintf("unknown status: %s", status)
	debugLog(b.debug, "BLACKLIST", "Host %s status %s: %s", host, status, reason)
	return false, reason
}

func (b *SmartBlacklist) IsBlacklisted(host string) bool {
	_, ok := b.blacklistedHosts.Load(host)
	return ok
}

func (b *SmartBlacklist) IsSuccessful(host string) bool {
	_, ok := b.successfulHosts.Load(host)
	return ok
}

func (b *SmartBlacklist) CleanupHost(host string) {
	b.consecutiveCount.Delete(host)
	b.totalCount.Delete(host)

	debugLog(b.debug, "BLACKLIST-CLEANUP", "Host %s: smart tracking removed", host)
}

func (b *SmartBlacklist) GetStats() map[string]interface{} {
	hostsTracked := 0
	b.consecutiveCount.Range(func(_, _ interface{}) bool {
		hostsTracked++
		return true
	})

	successfulHosts := 0
	b.successfulHosts.Range(func(_, _ interface{}) bool {
		successfulHosts++
		return true
	})

	blacklistedHosts := 0
	b.blacklistedHosts.Range(func(_, _ interface{}) bool {
		blacklistedHosts++
		return true
	})

	return map[string]interface{}{
		"blacklisted_hosts":    blacklistedHosts,
		"successful_hosts":     successfulHosts,
		"consecutive_triggers": atomic.LoadInt64(&b.stats.consecutiveTriggers),
		"total_triggers":       atomic.LoadInt64(&b.stats.totalTriggers),
		"total_hosts_tracked":  hostsTracked,
	}
}
// }}}
// {{{ SECTION 9: RESOURCE AWARE BATCHER
type ResourceAwareBatcher struct {
	ramLimitBytes    int64
	maxPerHost       int
	debug            bool

	hosts            []string
	users            []string
	passwords        []string
	protocols        []ProtocolConfig

	completedHosts   map[string]bool
}

type Batch struct {
	Index          int
	Total          int
	Hosts          []string
	Tasks          []Task
	EstimatedRAM   int64
}

func NewResourceAwareBatcher(hosts, users, passwords []string, protocols []ProtocolConfig,
	maxPerHost int, ramLimitBytes int64, completedHosts []string, debug bool) *ResourceAwareBatcher {

	completedMap := make(map[string]bool)
	for _, host := range completedHosts {
		completedMap[host] = true
	}

	return &ResourceAwareBatcher{
		ramLimitBytes:  ramLimitBytes,
		maxPerHost:     maxPerHost,
		debug:          debug,
		hosts:          hosts,
		users:          users,
		passwords:      passwords,
		protocols:      protocols,
		completedHosts: completedMap,
	}
}

func (b *ResourceAwareBatcher) calculateHostRAM(host string) int64 {
	tasksPerHost := len(b.users) * len(b.passwords) * len(b.protocols)

	bytesPerTask := int64(485)
	workerOverhead := int64(b.maxPerHost) * 5 * 1024
	hostOverhead := int64(2 * 1024)

	avgUsernameLen := averageStringLength(b.users)
	avgPasswordLen := averageStringLength(b.passwords)
	avgStringPerTask := int64(avgUsernameLen + avgPasswordLen + len(host) + 10)
	stringData := avgStringPerTask * int64(tasksPerHost)

	taskMemory := int64(tasksPerHost) * bytesPerTask
	total := taskMemory + workerOverhead + hostOverhead + stringData

	total = total * 27 / 25

	debugLog(b.debug, "RAM-CALC-AGGRESSIVE", "Host %s: %d tasks × %s/task = %s + %s worker + %s host = %s total",
		host, tasksPerHost, formatBytes(bytesPerTask), formatBytes(taskMemory),
		formatBytes(workerOverhead), formatBytes(hostOverhead), formatBytes(total))

	return total
}

func (b *ResourceAwareBatcher) generateTasksForHosts(hosts []string) []Task {
	var tasks []Task

	for _, proto := range b.protocols {
		if !proto.Enabled {
			continue
		}

		for _, username := range b.users {
			for _, password := range b.passwords {
				for _, host := range hosts {
					if b.completedHosts[host] {
						continue
					}

					taskID := fmt.Sprintf("%s:%s:%s@%s:%d", proto.Name, host, username, password, proto.Port)
					tasks = append(tasks, Task{
						Target:   host,
						Username: username,
						Password: password,
						Protocol: proto.Name,
						Port:     proto.Port,
						ID:       taskID,
					})
				}
			}
		}
	}

	return tasks
}

func (b *ResourceAwareBatcher) getActiveHosts() []string {
	var activeHosts []string
	for _, host := range b.hosts {
		if !b.completedHosts[host] {
			activeHosts = append(activeHosts, host)
		}
	}
	return activeHosts
}

func (b *ResourceAwareBatcher) createSingleBatch() []Batch {
	activeHosts := b.getActiveHosts()
	batch := b.createBatch(1, activeHosts)
	batch.Total = 1
	return []Batch{batch}
}

func (b *ResourceAwareBatcher) CreateBatches() []Batch {
	if b.ramLimitBytes <= 0 {
		debugLog(b.debug, "", "RAM unlimited, creating single batch")
		return b.createSingleBatch()
	}

	safeLimit := b.ramLimitBytes * 9 / 10
	fmt.Print(HeaderPlus("Calculating Memory...\n"))

	var batches []Batch
	var currentBatchHosts []string
	var currentRAM int64
	batchIndex := 1

	activeHosts := b.getActiveHosts()
	fmt.Printf(TreeBranch()+" "+("Active hosts to process: %d\n"), len(activeHosts))

	if len(activeHosts) == 0 {
		debugLog(b.debug, "BATCHER", "No active hosts to process")
		return batches
	}

	sampleHost := activeHosts[0]
	sampleHostRAM := b.calculateHostRAM(sampleHost)
	if sampleHostRAM > safeLimit {
		fmt.Printf("[ERROR] Single host requires %s, exceeds safe limit %s\n",
			formatBytes(sampleHostRAM), formatBytes(safeLimit))
		fmt.Printf("[ERROR] Increase RAM limit or reduce credential combinations\n")
		os.Exit(1)
	}

	estimatedHostsPerBatch := int(float64(safeLimit) / float64(sampleHostRAM))
	estimatedBatches := (len(activeHosts) + estimatedHostsPerBatch - 1) / estimatedHostsPerBatch
	fmt.Printf(TreeEnd()+" "+("Estimated: ~%d hosts per batch, ~%d batches total\n"), estimatedHostsPerBatch, estimatedBatches)

	for i, host := range activeHosts {
		hostRAM := b.calculateHostRAM(host)

		if b.debug && i > 0 && i%5000 == 0 {
			fmt.Printf("[BATCHER] Processed %d/%d hosts, current batch: %d hosts, %s RAM\n",
				i, len(activeHosts), len(currentBatchHosts), formatBytes(currentRAM))
		}

		if hostRAM > safeLimit {
			fmt.Printf("[WARNING] Host %s requires %s (> safe limit)\n",
				host, formatBytes(hostRAM))
			if len(currentBatchHosts) > 0 {
				batch := b.createBatch(batchIndex, currentBatchHosts)
				batches = append(batches, batch)
				currentBatchHosts = []string{}
				currentRAM = 0
				batchIndex++
			}
			batch := b.createBatch(batchIndex, []string{host})
			batches = append(batches, batch)
			batchIndex++
			continue
		}

		if currentRAM+hostRAM > safeLimit && len(currentBatchHosts) > 0 {
			batch := b.createBatch(batchIndex, currentBatchHosts)
			batches = append(batches, batch)

			currentBatchHosts = []string{host}
			currentRAM = hostRAM
			batchIndex++

			debugLog(b.debug, "BATCHER", "Created batch %d with %d hosts, %s RAM",
				batchIndex-1, len(batch.Hosts), formatBytes(currentRAM))
		} else {
			currentBatchHosts = append(currentBatchHosts, host)
			currentRAM += hostRAM
		}
	}

	if len(currentBatchHosts) > 0 {
		batch := b.createBatch(batchIndex, currentBatchHosts)
		batches = append(batches, batch)

		debugLog(b.debug, "BATCHER", "Created final batch %d with %d hosts, %s RAM",
			batchIndex, len(batch.Hosts), formatBytes(currentRAM))
	}

	for i := range batches {
		batches[i].Total = len(batches)
	}

	b.printBatchStats(batches, safeLimit)
	return batches
}

func (b *ResourceAwareBatcher) createBatch(index int, hosts []string) Batch {
	tasks := b.generateTasksForHosts(hosts)

	var estimatedRAM int64 = 0
	for _, host := range hosts {
		estimatedRAM += b.calculateHostRAM(host)
	}

	return Batch{
		Index:        index,
		Total:        0,
		Hosts:        hosts,
		Tasks:        tasks,
		EstimatedRAM: estimatedRAM,
	}
}

func (b *ResourceAwareBatcher) printBatchStats(batches []Batch, safeLimit int64) {
	if len(batches) == 0 {
		fmt.Printf("No batches created (all hosts already completed?)\n")
		return
	}

	totalHosts := 0
	totalTasks := 0
	maxBatchRAM := int64(0)

	for _, batch := range batches {
		estimatedRAM := int64(0)
		for _, host := range batch.Hosts {
			estimatedRAM += b.calculateHostRAM(host)
		}

		if estimatedRAM > maxBatchRAM {
			maxBatchRAM = estimatedRAM
		}

		percentOfLimit := float64(estimatedRAM) / float64(safeLimit) * 100

		fmt.Printf("     - %d/%d: %d hosts, %d tasks, %s RAM (%.1f%% of limit)\n",
			batch.Index, batch.Total,
			len(batch.Hosts), len(batch.Tasks),
			formatBytes(estimatedRAM), percentOfLimit)

		totalHosts += len(batch.Hosts)
		totalTasks += len(batch.Tasks)
	}

	if maxBatchRAM > safeLimit {
		fmt.Printf("     - [WARNING] Largest batch uses %s (> safe limit %s)\n",
			formatBytes(maxBatchRAM), formatBytes(safeLimit))
		fmt.Printf("     - [WARNING] Consider increasing RAM limit\n")
	} else if maxBatchRAM > safeLimit*9/10 {
		fmt.Printf("     - [NOTE] Largest batch uses %s (close to limit %s)\n",
			formatBytes(maxBatchRAM), formatBytes(safeLimit))
	} else {
		fmt.Printf("     - [OK] All batches within safe limit (%s)\n",
			formatBytes(safeLimit))
	}
}
// }}}
// {{{ SECTION 10: WORKER & STATUS
var (
	retryableStatuses = map[string]bool{
		"timeout":                            true,
		"banner-timeout":                     true,
		"connection-reset":                   true,
		"conn-reset":                         true,
		"handshake-error":                    true,
		"handshake-failed":                   true,
		"key-exchange-failed":                true,
		"connection-aborted":                 true,
		"too-many-connections":               true,
		"service-not-available":              true,
		"resource-temporarily-unavailable":   true,
		"ftp-protocol-error":                 true,
		"ftp-error":                          true,
		"connection-error":                   true,
		"send-error":                         true,
		"protocol-error":                     true,
		"network-error":                      true,
		"read-timeout":                       true,
		"write-timeout":                      true,
		"protocol-mismatch":                  true,
	}

	allFalseNegatives = map[string]string{
		"timeout":                           "Connection timeout",
		"banner-timeout":                    "SSH banner timeout",
		"connection-refused":                "Connection refused",
		"connection-reset":                  "Connection reset by peer",
		"conn-reset":                        "Connection reset by peer",
		"host-down":                         "Host is down",
		"network-unreachable":               "Network unreachable",
		"protocol-mismatch":                 "Protocol version mismatch",
		"handshake-error":                   "SSH handshake error",
		"handshake-failed":                  "SSH handshake failed",
		"key-exchange-failed":               "SSH key exchange failed",
		"connection-aborted":                "Connection aborted",
		"too-many-connections":              "Too many connections",
		"service-not-available":             "Service not available",
		"resource-temporarily-unavailable":  "Resource temporarily unavailable",
		"ftp-protocol-error":                "FTP Protocol error",
		"ftp-error":                         "FTP Error",
		"connection-error":                  "Connection error",
		"send-error":                        "Telnet send error",
		"protocol-error":                    "Protocol communication error",
		"network-error":                     "Network communication error",
		"read-timeout":                      "Read timeout",
		"write-timeout":                     "Write timeout",
		"no-route":                          "No route to host",
	}

	authFailedStatuses = map[string]bool{
		"auth-failed":           true,
		"invalid-credentials":   true,
		"access-denied":         true,
		"login-incorrect":       true,
		"wrong-password":        true,
		"authentication-failed": true,
		"authorization-failed":  true,
		"permission-denied":     true,
		"account-locked":        true,
		"password-expired":      true,
		"user-disabled":         true,
	}

	successStatuses = map[string]bool{
		"success":        true,
		"authenticated":  true,
		"logged-in":      true,
		"access-granted": true,
		"shell-access":   true,
	}
)

func IsRetryableStatus(status string) bool {
	return retryableStatuses[status]
}

func IsAuthFailedStatus(status string) bool {
	return authFailedStatuses[status]
}

func IsSuccessStatus(status string) bool {
	return successStatuses[status]
}

func GetStatusDescription(status string) string {
	if desc, ok := allFalseNegatives[status]; ok {
		return desc
	}
	return "Unknown status"
}

type Worker struct {
	id             int
	engine         *Engine
	currentHost    string
	tasksProcessed int
}

type WorkerPool struct {
	workers   []*Worker
	available chan *Worker
	debug     bool
}

func NewWorkerPool(engine *Engine, numWorkers int, debug bool) *WorkerPool {
	pool := &WorkerPool{
		workers:   make([]*Worker, numWorkers),
		available: make(chan *Worker, numWorkers),
		debug:     debug,
	}

	for i := 0; i < numWorkers; i++ {
		worker := &Worker{
			id:     i,
			engine: engine,
		}
		pool.workers[i] = worker
		pool.available <- worker
	}

	debugLog(debug, "WORKER-POOL", "Created %d persistent workers", numWorkers)

	return pool
}

func (wp *WorkerPool) allocateWorkers(count int) []*Worker {
	workers := make([]*Worker, count)
	for i := 0; i < count; i++ {
		workers[i] = <-wp.available
	}
	return workers
}

func (wp *WorkerPool) releaseWorkers(workers []*Worker) {
	for _, worker := range workers {
		wp.available <- worker
	}
}

func (wp *WorkerPool) Stop() {
	debugLog(wp.debug, "WORKER-POOL", "Pool stopped")
}
// }}}
// {{{ SECTION 11: COMMAND & SCRIPT EXECUTOR
type CommandExecutor struct {
	config *Config
	debug  bool}
func NewCommandExecutor(config *Config, debug bool) *CommandExecutor {
	return &CommandExecutor{
		config: config,
		debug:  debug,}}
func (ce *CommandExecutor) ExecuteCommand(task Task) string {
	if ce.config.Command == "" {
	return ""}
	return ExecuteCommandForTask(task, ce.config.Command, ce.config.Timeout, ce.config.Debug)}
// Script executor
type ScriptExecutor struct {
	scriptPath string
	debug      bool}
func NewScriptExecutor(scriptPath string, debug bool) *ScriptExecutor {
	return &ScriptExecutor{
		scriptPath: scriptPath,
		debug:      debug,}}
func (se *ScriptExecutor) Execute() error {
	if se.scriptPath == "" {
	return nil}
	debugLog(se.debug, "SCRIPT-EXECUTOR", "Executing script: %s", se.scriptPath)
	cmd := exec.Command(se.scriptPath, os.Args[0:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
	return fmt.Errorf("script execution failed: %v", err)}
	return nil}
func (se *ScriptExecutor) ShouldExit() bool {
	return se.scriptPath != ""}
// }}}
// {{{ SECTION 12: ENGINE CORE
type Engine struct {
	config      *Config
	blacklist   *SmartBlacklist
	progress    *ProgressManager
	progressBar *ProgressBar
	totalTasks  int
	interrupted bool

	cmdExecutor *CommandExecutor
	workerPool  *WorkerPool

	resultFile   *os.File
	resultWriter *csv.Writer
	resultMutex  sync.Mutex

	stats struct {
		tasksProcessed    int64
		autoSkips         int64
		localRetries      int64
		falseNegatives    int64
		retryableFN       int64
		nonRetryableFN    int64
		authFailures      int64
		successes         int64
		hostsTested       int64
		blacklistAdded    int64
		resultsWritten    int64
	}

	sigChan chan os.Signal
}

func NewEngine(config *Config) *Engine {
	engine := &Engine{
		config:    config,
		blacklist: NewSmartBlacklist(config.MaxConsecutiveFN, config.MaxTotalFN, config.Debug),
	}

	engine.cmdExecutor = NewCommandExecutor(config, config.Debug)
	engine.progress = NewProgressManager("progress.json", config.Debug)
	engine.progressBar = NewProgressBar(config.Debug, config.Mute)
	engine.workerPool = NewWorkerPool(engine, config.MaxThreads, config.Debug)
	engine.initializeResultFile()

	return engine
}

func (e *Engine) initializeResultFile() {
	fileExists := false
	if _, err := os.Stat(e.config.OutputFile); err == nil {
		fileExists = true
	}

	file, err := os.OpenFile(e.config.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[ERROR] Failed to open result file: %v\n", err)
		return
	}

	e.resultFile = file
	e.resultWriter = csv.NewWriter(file)

	if !fileExists {
		header := []string{
			"timestamp",
			"target",
			"username",
			"password",
			"protocol",
			"port",
			"status",
			"latency",
			"error",
			"command_output",
		}
		if err := e.resultWriter.Write(header); err != nil {
			fmt.Printf("[ERROR] Failed to write header: %v\n", err)
		} else {
			e.resultWriter.Flush()
		}
	}

	debugLog(e.config.Debug, "RESULT", "Result file opened: %s (append mode)", e.config.OutputFile)
}

func (e *Engine) writeResultImmediately(result Result) {
	if e.resultWriter == nil {
		return
	}

	e.resultMutex.Lock()
	defer e.resultMutex.Unlock()

	record := []string{
		result.Timestamp,
		result.Target,
		result.Username,
		result.Password,
		result.Protocol,
		strconv.Itoa(result.Port),
		result.Status,
		strconv.FormatFloat(result.Latency, 'f', 6, 64),
		result.Error,
		result.CommandOutput,
	}

	if err := e.resultWriter.Write(record); err != nil {
		debugLog(e.config.Debug, "WRITE-ERROR", "Failed to write result: %v", err)
		return
	}

	e.resultWriter.Flush()

	if err := e.resultFile.Sync(); err != nil && e.config.Debug {
		debugLog(e.config.Debug, "WRITE-ERROR", "Failed to sync file: %v", err)
	}

	atomic.AddInt64(&e.stats.resultsWritten, 1)

	debugLog(e.config.Debug, "WRITE", "Result saved: %s@%s:%d",
		result.Username, result.Target, result.Port)
}

func (e *Engine) closeResultFile() {
	if e.resultWriter != nil {
		e.resultWriter.Flush()
	}
	if e.resultFile != nil {
		e.resultFile.Close()
	}
}

func (e *Engine) setupSignalHandler() {
	e.sigChan = make(chan os.Signal, 1)
	signal.Notify(e.sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-e.sigChan
		e.interrupted = true
		e.progressBar.Disable()

		fmt.Print("\r")
		fmt.Printf(BoldCyan("(x__x)")+" Praying : %v", sig)
		time.Sleep(2500 * time.Millisecond)

		fmt.Print(BoldCyan("\rd-(^_^)z") + " Cooking something before exit...")
		time.Sleep(2500 * time.Millisecond)

		e.closeResultFile()
		e.workerPool.Stop()

		pbStats := e.progressBar.GetStats()

		var blacklistedHosts, successfulHosts []string

		e.blacklist.blacklistedHosts.Range(func(key, value interface{}) bool {
			if host, ok := key.(string); ok {
				blacklistedHosts = append(blacklistedHosts, host)
			}
			return true
		})

		e.blacklist.successfulHosts.Range(func(key, value interface{}) bool {
			if host, ok := key.(string); ok {
				successfulHosts = append(successfulHosts, host)
			}
			return true
		})

		if err := e.progress.Save(pbStats, blacklistedHosts, successfulHosts); err != nil {
			fmt.Printf(BoldCyan("\r(-_-)")+" Failed to save progress: %v\n", err)
		} else {
			fmt.Print(BoldCyan("\r(o_^)") + " Progress saved to: progress.json")
			time.Sleep(2500 * time.Millisecond)
			fmt.Print("\r")
			fmt.Print(BoldCyan("(>_>)") + " Resume with same command or tuning configuration")
			time.Sleep(2500 * time.Millisecond)
			fmt.Println()
		}

		os.Exit(0)
	}()
}

func (e *Engine) loadAndFilterTargets() ([]string, int, error) {
	allTargets, err := loadLines(e.config.TargetsFile)
	if err != nil {
		return nil, 0, err
	}

	if e.config.NoResume {
		return allTargets, 0, nil
	}

	var activeTargets []string
	skippedCount := 0

	for _, target := range allTargets {
		if e.progress.IsCompleted(target) {
			skippedCount++
			debugLog(e.config.Debug, "RESUME", "Skipping completed host: %s", target)
		} else {
			activeTargets = append(activeTargets, target)
		}
	}

	return activeTargets, skippedCount, nil
}

func (e *Engine) generateTasks(targets, users, passwords []string) []Task {
	var tasks []Task

	for _, proto := range e.config.Protocols {
		if !proto.Enabled {
			continue
		}

		for _, username := range users {
			for _, password := range passwords {
				for _, target := range targets {
					taskID := fmt.Sprintf("%s:%s:%s@%s:%d", proto.Name, target, username, password, proto.Port)
					tasks = append(tasks, Task{
						Target:   target,
						Username: username,
						Password: password,
						Protocol: proto.Name,
						Port:     proto.Port,
						ID:       taskID,
					})
				}
			}
		}
	}

	return tasks
}

func (e *Engine) processBatch(ctx context.Context, batch Batch, results chan<- Result) {
	debugLog(e.config.Debug, "", "Processing batch %d/%d: %d hosts, %d tasks",
		batch.Index, batch.Total, len(batch.Hosts), len(batch.Tasks))

	tasksByHost := make(map[string][]Task)
	for _, task := range batch.Tasks {
		tasksByHost[task.Target] = append(tasksByHost[task.Target], task)
	}

	var hostsWg sync.WaitGroup

	maxConcurrentHosts := e.config.MaxThreads / e.config.MaxPerHost
	if maxConcurrentHosts < 1 {
		maxConcurrentHosts = 1
	}
	hostSemaphore := make(chan struct{}, maxConcurrentHosts)

	for host, hostTasks := range tasksByHost {
		if e.blacklist.IsSuccessful(host) || e.blacklist.IsBlacklisted(host) {
			skipCount := len(hostTasks)
			atomic.AddInt64(&e.stats.autoSkips, int64(skipCount))
			e.progressBar.AddBatchSkips(skipCount)
			continue
		}

		hostsWg.Add(1)

		go func(h string, ht []Task) {
			defer hostsWg.Done()

			hostSemaphore <- struct{}{}
			defer func() { <-hostSemaphore }()

			e.processHostTasks(ctx, h, ht)
		}(host, hostTasks)
	}

	hostsWg.Wait()
	e.progressBar.BatchCompleted(len(batch.Hosts), len(batch.Tasks))
}

func (e *Engine) processHostTasks(ctx context.Context, host string, tasks []Task) {
	debugLog(e.config.Debug, "HOST", "%s allocated %d workers", host, e.config.MaxPerHost)

	if e.progress.IsCompleted(host) {
		debugLog(e.config.Debug, "HOST", "Skipping already completed host: %s", host)
		return
	}

	if e.blacklist.IsSuccessful(host) || e.blacklist.IsBlacklisted(host) {
		skipCount := len(tasks)
		atomic.AddInt64(&e.stats.autoSkips, int64(skipCount))
		e.progressBar.AddBatchSkips(skipCount)

		e.blacklist.CleanupHost(host)

		return
	}

	atomic.AddInt64(&e.stats.hostsTested, 1)
	e.progressBar.Update(false, true, false, false, false)

	workersNeeded := e.config.MaxPerHost
	if workersNeeded > len(tasks) {
		workersNeeded = len(tasks)
	}

	if workersNeeded == 0 {
		return
	}

	workers := e.workerPool.allocateWorkers(workersNeeded)
	defer e.workerPool.releaseWorkers(workers)

	debugLog(e.config.Debug, "HOST", "%s allocated %d workers", host, len(workers))

	taskChan := make(chan Task, len(tasks))
	for _, task := range tasks {
		taskChan <- task
	}
	close(taskChan)

	var workersWg sync.WaitGroup
	for _, worker := range workers {
		workersWg.Add(1)

		go func(w *Worker) {
			defer workersWg.Done()

			w.currentHost = host
			defer func() { w.currentHost = "" }()

			for task := range taskChan {
				if ctx.Err() != nil {
					return
				}

				if e.blacklist.IsSuccessful(host) || e.blacklist.IsBlacklisted(host) {
					atomic.AddInt64(&e.stats.autoSkips, 1)
					e.progressBar.Update(false, false, false, false, true)
					continue
				}

				e.processTaskWithWorker(w, task)
				w.tasksProcessed++
			}
		}(worker)
	}

	workersWg.Wait()

	if !e.interrupted {
		e.progress.AddCompletedHost(host)
		e.blacklist.CleanupHost(host)

		debugLog(e.config.Debug, "HOST-COMPLETE", "Host %s: all tasks completed, smart tracking cleaned", host)
	}
}

func (e *Engine) processTaskWithWorker(worker *Worker, task Task) {
	config := e.config

	if config.BaseDelay > 0 {
		time.Sleep(time.Duration(config.BaseDelay * float64(time.Second)))
	}

	var tested, blacklisted, success bool

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		attemptNum := attempt + 1

		tester := createProtocolTester(task.Protocol, config.Timeout, config.Debug)
		if tester == nil {
			debugLog(config.Debug, "", "Unknown protocol: %s, skipping", task.Protocol)
			break
		}

		status, latency, errorMsg := tester.Test(task.Target, task.Port, task.Username, task.Password)

		timestamp := time.Now().Format(time.RFC3339)
		result := Result{
			Timestamp: timestamp,
			Target:    task.Target,
			Username:  task.Username,
			Password:  task.Password,
			Protocol:  task.Protocol,
			Port:      task.Port,
			Status:    status,
			Latency:   latency,
			Error:     errorMsg,
		}

		isBlacklisted, reason := e.blacklist.ProcessResult(task.Target, status)
		blacklisted = isBlacklisted

		if config.Debug {
			if strings.Contains(reason, "blacklisted") ||
				strings.Contains(reason, "reset consecutive counter") ||
				strings.Contains(reason, "consecutive false negatives") ||
				strings.Contains(reason, "total false negatives") {
				debugLog(config.Debug, "BLACKLIST", "Host %s status %s: %s", task.Target, status, reason)
			}
		}

		if isBlacklisted {
			atomic.AddInt64(&e.stats.blacklistAdded, 1)
			tested = true
			break
		}

		if e.blacklist.isSuccess(status) {
			atomic.AddInt64(&e.stats.successes, 1)
			success = true

			commandOutput := ""
			if e.config.Command != "" && (task.Protocol == "ssh" || task.Protocol == "telnet") {
				commandOutput = e.cmdExecutor.ExecuteCommand(task)

				if e.config.Debug && commandOutput != "" {
					debugLog(config.Debug, "CMD-DEBUG", "%s command output (len=%d): %s",
						task.Username, len(commandOutput), commandOutput)
				}
			}

			successMsg := fmt.Sprintf("%s://%s:%d - %s:%s",
				task.Protocol, task.Target, task.Port, task.Username, task.Password)

			if commandOutput != "" && len(commandOutput) < 50 {
				successMsg += fmt.Sprintf(" [CMD: %s]", commandOutput)
			}

			e.progressBar.AddSuccessMessage(successMsg)
			tested = true

			result.CommandOutput = commandOutput
			e.writeResultImmediately(result)
			break
		} else if e.blacklist.isAuthFailed(status) {
			atomic.AddInt64(&e.stats.authFailures, 1)
			tested = true
			break
		} else if e.blacklist.isFalseNegative(status) {
			if e.blacklist.isRetryable(status) {
				atomic.AddInt64(&e.stats.retryableFN, 1)

				if attempt < config.MaxRetries {
					atomic.AddInt64(&e.stats.localRetries, 1)

					var delay float64
					if config.ExponentialBackoff {
						delay = config.RetryDelay * math.Pow(2, float64(attempt))
					} else {
						delay = config.RetryDelay
					}

					debugLog(config.Debug, "RETRY", "Worker-%d attempt %d/%d for %s - delay %.1fs",
						worker.id, attemptNum, config.MaxRetries+1, task.ID, delay)

					if delay > 0 {
						time.Sleep(time.Duration(delay * float64(time.Second)))
					}
					continue
				}
			} else {
				atomic.AddInt64(&e.stats.nonRetryableFN, 1)
			}

			atomic.AddInt64(&e.stats.falseNegatives, 1)
			tested = true
			break
		} else {
			tested = true
			break
		}
	}

	if tested {
		atomic.AddInt64(&e.stats.tasksProcessed, 1)
		e.progressBar.Update(true, false, success, blacklisted, false)
	}
}

func (e *Engine) Run() error {
	e.interrupted = false
	defer e.closeResultFile()
	defer e.workerPool.Stop()

	configHash, err := CalculateConfigHash(
		e.config.TargetsFile,
		e.config.UsersFile,
		e.config.PasswordsFile,
		e.config.Protocols,
	)
	if err != nil {
		return fmt.Errorf("failed to calculate config hash: %v", err)
	}

	e.progress.SetConfigHash(configHash)

	var loadedStats map[string]interface{}
	var loadedBlacklistedHosts, loadedSuccessfulHosts []string

	if !e.config.NoResume {
		loaded, msg, stats, blacklistedHosts, successfulHosts := e.progress.Load(configHash)
		if loaded {
			if !e.config.Mute {
				fmt.Println(HeaderPlus("Resume: Loaded previous progress (" + msg + ")"))
			}
			loadedStats = stats
			loadedBlacklistedHosts = blacklistedHosts
			loadedSuccessfulHosts = successfulHosts

			completedHosts := e.progress.GetCompletedHosts()
			for _, host := range completedHosts {
				e.blacklist.CleanupHost(host)
			}

			debugLog(e.config.Debug, "RESUME-CLEANUP", "Cleaned %d previously completed hosts",
				len(completedHosts))
		} else if strings.Contains(msg, "config hash mismatch") {
			if e.config.ForceResume {
				if !e.config.Mute {
					fmt.Println(HeaderWarning("WARNING: Config changed but forcing resume (" + msg + ")"))
				}
				e.progress.Cleanup()
			} else {
				fmt.Println(HeaderWarning("WARNING: " + msg))
				fmt.Println(HeaderWarning("Configuration files have changed since last run"))
				fmt.Println(HeaderWarning("Resume may skip untested combinations"))
				fmt.Println(HeaderWarning("Use --force-resume to continue anyway"))
				fmt.Println(HeaderWarning("Or use --no-resume to start fresh"))
				return fmt.Errorf("config changed, use --force-resume to continue")
			}
		} else if msg != "no progress file" {
			if !e.config.Mute {
				fmt.Println(HeaderWarning("WARNING: Failed to load progress: %s" + msg))
				fmt.Println(HeaderWarning("Starting fresh scan"))
			}
		}
	}

	targets, skippedCount, err := e.loadAndFilterTargets()
	if err != nil {
		return fmt.Errorf("failed to load targets: %v", err)
	}

	if len(targets) == 0 {
		if !e.config.Mute {
			stats := e.progress.GetCompletedStats()
			if total, ok := stats["total_completed"].(int); ok {
				fmt.Println(HeaderPlus("All hosts already completed"))
				fmt.Println(TreeSpace() + Cyan("Completed hosts: ") + FormatConfigNumber(total))
				fmt.Println(TreeSpace() + Cyan("Use --no-resume to start fresh"))
			}
		}
		if e.config.Debug {
			printMemoryDebug(true, "FINAL-MEMORY")
		}
		return nil
	}

	users, err := loadLines(e.config.UsersFile)
	if err != nil {
		return fmt.Errorf("failed to load users: %v", err)
	}

	passwords, err := loadLines(e.config.PasswordsFile)
	if err != nil {
		return fmt.Errorf("failed to load passwords: %v", err)
	}

	enabledProtocols := 0
	for _, proto := range e.config.Protocols {
		if proto.Enabled {
			enabledProtocols++
		}
	}

	if enabledProtocols == 0 {
		return fmt.Errorf("no protocol enabled. Use --ssh or --ftp")
	}

	e.setupSignalHandler()

	tasks := e.generateTasks(targets, users, passwords)
	totalTasks := len(tasks)
	e.totalTasks = totalTasks

	tasksByHost := make(map[string][]Task)
	for _, task := range tasks {
		tasksByHost[task.Target] = append(tasksByHost[task.Target], task)
	}

	uniqueHosts := len(tasksByHost)

	progressStats := e.progress.GetCompletedStats()
	completedHosts := 0
	if total, ok := progressStats["total_completed"].(int); ok {
		completedHosts = total
	}

	completedHostsList := e.progress.GetCompletedHosts()

	initialSkips := 0
	for _, host := range completedHostsList {
		if hostTasks, exists := tasksByHost[host]; exists {
			initialSkips += len(hostTasks)
		}
	}

	useBatching := e.config.RAMLimitBytes > 0

	if useBatching {
		if !e.config.Mute {
			fmt.Println(HeaderPlus("Mode: ") + Magenta("BATCHED") +
				Cyan(" (RAM limit: ") + formatBytes(e.config.RAMLimitBytes) + Cyan(")"))
		}

		batcher := NewResourceAwareBatcher(
			targets,
			users,
			passwords,
			e.config.Protocols,
			e.config.MaxPerHost,
			e.config.RAMLimitBytes,
			completedHostsList,
			e.config.Debug,
		)

		batches := batcher.CreateBatches()
		totalBatches := len(batches)

		if totalBatches == 0 {
			if !e.config.Mute {
				fmt.Println(HeaderPlus("No batches to process (all hosts already completed?)"))
			}
			return nil
		}

		e.progressBar.Initialize(totalTasks, uniqueHosts, completedHosts, totalBatches)

		debugLog(e.config.Debug, "ENGINE", "Batched mode: %d batches, RAM limit: %s",
			totalBatches, formatBytes(e.config.RAMLimitBytes))

		if loadedStats != nil {
			e.progressBar.mu.Lock()
			if val, ok := loadedStats["success_count"].(int64); ok {
				e.progressBar.successCount = val
			}
			if val, ok := loadedStats["blacklist_count"].(int64); ok {
				e.progressBar.blacklistCount = val
			}
			if val, ok := loadedStats["skip_count"].(int64); ok {
				e.progressBar.skipCount = val
			}
			if val, ok := loadedStats["tasks_processed"].(int64); ok {
				e.progressBar.tasksProcessed = val
			}
			if val, ok := loadedStats["hosts_tested"].(int64); ok {
				e.progressBar.hostsTested = val
			}
			e.progressBar.mu.Unlock()
		}

		if loadedBlacklistedHosts != nil {
			for _, host := range loadedBlacklistedHosts {
				e.blacklist.blacklistedHosts.Store(host, true)
			}
		}
		if loadedSuccessfulHosts != nil {
			for _, host := range loadedSuccessfulHosts {
				e.blacklist.successfulHosts.Store(host, true)
			}
		}
		if initialSkips > 0 {
			e.progressBar.AddBatchSkips(initialSkips)
			atomic.AddInt64(&e.stats.autoSkips, int64(initialSkips))

			debugLog(e.config.Debug, "RESUME", "Skipping %d tasks from %d completed hosts",
				initialSkips, completedHosts)
		}

		if !e.config.Mute {
			fmt.Println(HeaderPlus(fmt.Sprintf("Loaded %s active targets (+%s skipped from previous runs)",
				FormatConfigNumber(len(targets)), FormatConfigNumber(skippedCount))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Completed hosts from previous runs: %s",
				FormatConfigNumber(completedHosts))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Pre-skipped tasks: %s",
				FormatConfigNumber(initialSkips))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Loaded %s users, %s passwords",
				FormatConfigNumber(len(users)), FormatConfigNumber(len(passwords)))))

			protocolsInfo := ""
			for _, proto := range e.config.Protocols {
				if proto.Enabled {
					if protocolsInfo != "" {
						protocolsInfo += ", "
					}
					protocolsInfo += fmt.Sprintf("%s:%d", proto.Name, proto.Port)
				}
			}
			fmt.Println(HeaderPlus(fmt.Sprintf("Total combinations: %s",
				FormatConfigNumber(int64(totalTasks)))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Total batches: %s",
				FormatConfigNumber(totalBatches))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Output file: %s",
				FormatConfigNumber(e.config.OutputFile))))

			maxWorkersPerHost := e.config.MaxPerHost
			totalWorkersNeeded := uniqueHosts * maxWorkersPerHost

			optimalWorkers := totalWorkersNeeded
			if optimalWorkers > e.config.MaxThreads {
				optimalWorkers = e.config.MaxThreads
			}

			fmt.Println(HeaderPlus(fmt.Sprintf("Host distribution: %s hosts × %s workers/host = %s workers needed",
				FormatConfigNumber(uniqueHosts), FormatConfigNumber(maxWorkersPerHost),
				FormatConfigNumber(totalWorkersNeeded))))
			fmt.Println()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for batchIndex, batch := range batches {
			if e.interrupted {
				break
			}

			e.progressBar.SetCurrentBatch(batchIndex+1, totalBatches)

			debugLog(e.config.Debug, "", "Starting batch %d/%d with %d hosts, %d tasks",
				batch.Index, batch.Total, len(batch.Hosts), len(batch.Tasks))

			e.processBatch(ctx, batch, nil)

			if !e.config.NoResume && !e.interrupted {
				pbStats := e.progressBar.GetStats()

				var blacklistedHosts, successfulHosts []string
				e.blacklist.blacklistedHosts.Range(func(key, value interface{}) bool {
					if host, ok := key.(string); ok {
						blacklistedHosts = append(blacklistedHosts, host)
					}
					return true
				})

				e.blacklist.successfulHosts.Range(func(key, value interface{}) bool {
					if host, ok := key.(string); ok {
						successfulHosts = append(successfulHosts, host)
					}
					return true
				})

				if err := e.progress.Save(pbStats, blacklistedHosts, successfulHosts); err != nil && e.config.Debug {
					debugLog(e.config.Debug, "PROGRESS", "Batch auto-save error: %v", err)
				}
			}
		}

		e.progressBar.Finalize()

		if !e.config.NoResume && !e.interrupted {
			if err := e.progress.Cleanup(); err != nil {
				if !e.config.Mute {
					fmt.Printf(HeaderPlus("Cleanup failed %v\n"), err)
				}
			} else {
				if !e.config.Mute {
					fmt.Println(HeaderPlus("Cleaneup ok.."))
				}
			}
		}

		e.printStatistics(totalTasks, 0, completedHosts)

	} else {
		debugLog(e.config.Debug, "ENGINE", "Unbatched mode (legacy behavior)")

		e.progressBar.Initialize(totalTasks, uniqueHosts, completedHosts, 1)

		if loadedStats != nil {
			e.progressBar.mu.Lock()
			if val, ok := loadedStats["success_count"].(int64); ok {
				e.progressBar.successCount = val
			}
			if val, ok := loadedStats["blacklist_count"].(int64); ok {
				e.progressBar.blacklistCount = val
			}
			if val, ok := loadedStats["skip_count"].(int64); ok {
				e.progressBar.skipCount = val
			}
			if val, ok := loadedStats["tasks_processed"].(int64); ok {
				e.progressBar.tasksProcessed = val
			}
			if val, ok := loadedStats["hosts_tested"].(int64); ok {
				e.progressBar.hostsTested = val
			}
			e.progressBar.mu.Unlock()
		}

		if loadedBlacklistedHosts != nil {
			for _, host := range loadedBlacklistedHosts {
				e.blacklist.blacklistedHosts.Store(host, true)
			}
		}
		if loadedSuccessfulHosts != nil {
			for _, host := range loadedSuccessfulHosts {
				e.blacklist.successfulHosts.Store(host, true)
			}
		}
		if initialSkips > 0 {
			e.progressBar.AddBatchSkips(initialSkips)
			atomic.AddInt64(&e.stats.autoSkips, int64(initialSkips))

			debugLog(e.config.Debug, "RESUME", "Skipping %d tasks from %d completed hosts",
				initialSkips, completedHosts)
		}

		if !e.config.Mute {
			fmt.Println(HeaderPlus(fmt.Sprintf("Loaded %s active targets (+%s skipped from previous runs)",
				FormatConfigNumber(len(targets)), FormatConfigNumber(skippedCount))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Completed hosts from previous runs: %s",
				FormatConfigNumber(completedHosts))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Pre-skipped tasks: %s",
				FormatConfigNumber(initialSkips))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Loaded %s users, %s passwords",
				FormatConfigNumber(len(users)), FormatConfigNumber(len(passwords)))))

			protocolsInfo := ""
			for _, proto := range e.config.Protocols {
				if proto.Enabled {
					if protocolsInfo != "" {
						protocolsInfo += ", "
					}
					protocolsInfo += fmt.Sprintf("%s:%d", proto.Name, proto.Port)
				}
			}
			fmt.Println(HeaderPlus(fmt.Sprintf("Total combinations: %s",
				FormatConfigNumber(int64(totalTasks)))))
			fmt.Println(HeaderPlus(fmt.Sprintf("Output file: %s",
				FormatConfigNumber(e.config.OutputFile))))
			fmt.Println()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var hostsWg sync.WaitGroup
		hostSemaphore := make(chan struct{}, e.config.MaxThreads/e.config.MaxPerHost)

		for host, hostTasks := range tasksByHost {
			if e.progress.IsCompleted(host) {
				continue
			}

			if e.blacklist.IsSuccessful(host) || e.blacklist.IsBlacklisted(host) {
				skipCount := len(hostTasks)
				atomic.AddInt64(&e.stats.autoSkips, int64(skipCount))
				e.progressBar.AddBatchSkips(skipCount)
				continue
			}

			hostsWg.Add(1)

			go func(h string, ht []Task) {
				defer hostsWg.Done()

				hostSemaphore <- struct{}{}
				defer func() { <-hostSemaphore }()

				e.processHostTasks(ctx, h, ht)
			}(host, hostTasks)
		}

		hostsWg.Wait()

		e.progressBar.Finalize()

		if !e.config.NoResume && !e.interrupted {
			if err := e.progress.Cleanup(); err != nil {
				if !e.config.Mute {
					fmt.Printf(HeaderPlus("Cleanup failed %v\n"), err)
				}
			} else {
				if !e.config.Mute {
					fmt.Println(HeaderPlus("Cleanup ok."))
				}
			}
		}

		e.printStatistics(totalTasks, 0, completedHosts)
	}

	return nil
}

func (e *Engine) printStatistics(totalTasks, successCount, completedHosts int) {
	if e.config.Mute {
		return
	}

	if !e.config.NoResume {
		if e.interrupted {
			fmt.Println("Scan interrupted - saved for resume")
		} else {
			fmt.Println("\n" + HeaderSuccess("Scan completed successfully"))
		}
	}

	pbStats := e.progressBar.GetStats()

	fmt.Println(TreeBranch() + " " + ("Total tasks: ") + FormatConfigNumber(int64(totalTasks)))
	fmt.Println(TreeBranch() + " " + ("Tasks processed: ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.tasksProcessed)))
	fmt.Println(TreeBranch() + " " + ("Tasks skipped: ") + FormatConfigNumber(pbStats["tasks_skipped"].(int64)))
	fmt.Println(TreeEnd() + " " + ("Completed hosts (this run + previous): ") + FormatConfigNumber(completedHosts))
	fmt.Println("\n" + HeaderInfo("Smart Blacklist Statistics:"))
	blacklistStats := e.blacklist.GetStats()
	fmt.Println(TreeBranch() + " " + ("Hosts tracked: ") + FormatConfigNumber(blacklistStats["total_hosts_tracked"]))
	fmt.Println(TreeBranch() + " " + ("Blacklisted hosts: ") + FormatConfigNumber(blacklistStats["blacklisted_hosts"]))
	fmt.Println(TreeBranch() + " " + ("Consecutive triggers: ") + FormatConfigNumber(blacklistStats["consecutive_triggers"]))
	fmt.Println(TreeEnd() + " " + ("Total triggers: ") + FormatConfigNumber(blacklistStats["total_triggers"]))
	fmt.Println("\n" + HeaderInfo("Performance Statistics:"))
	fmt.Println(TreeBranch() + " " + ("Local retries: ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.localRetries)))
	fmt.Println(TreeBranch() + " " + ("False negatives: ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.falseNegatives)))
	fmt.Println(TreeBranch() + " " + ("Retryable (timeout/reset): ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.retryableFN)))
	fmt.Println(TreeBranch() + " " + ("Non-retryable (refused/down): ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.nonRetryableFN)))
	fmt.Println(TreeBranch() + " " + ("Auth failures: ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.authFailures)))
	fmt.Println(TreeEnd() + " " + ("Successes: ") + FormatConfigNumber(atomic.LoadInt64(&e.stats.successes)))

	printMemoryReport(false)
}
// }}}
// {{{ SECTION 13: UI COMPONENTS
func printAnimatedBanner() {
	//fmt.Print("\033c\033[3J")

	title := "M I N O T A U R   M O O D"
	colors := []string{ColorWhite, ColorMagenta, ColorCyan}

	fmt.Print("\n\n         ")
	for i, char := range title {
		if char == ' ' {
			fmt.Print(" ")
			time.Sleep(20 * time.Millisecond)
			continue
		}
		color := colors[i%len(colors)]
		fmt.Printf("%s%c%s", color, char, ColorReset)
		time.Sleep(30 * time.Millisecond)
	}
	fmt.Print("\n\n      ")

	now := time.Now()
	dayOfMonth := now.Day()
	moods := []string{
		"😠 Bad mood today... everything sucks",
		"😊 Good mood today! Ready to hunt",
		"😄 Happy mood! Let's brute force!",
		"😤 Angry mood! RARRR!",
		"😐 No mood today. Just existing.",
		"😴 Lazy mood... can't be bothered",
		"😍 Minotaur is in love today! 💕",
		"🤔 Thinking mood... hmm...",
		"🚀 Turbo mood! Let's go fast!",
		"🛡️ Defensive mood... be careful",
		"🎯 Focused mood. One shot one kill.",
		"💀 Grim mood... nothing matters",
		"⚡ Electric mood! Full of energy today",
		"🌙 Night mood... peaceful hunting",
		"☀️ Day mood... bright and clear",
		"🌧️ Rainy mood... melancholic",
		"🔥 Fire mood! Burning passion!",
		"❄️ Cold mood... icy and calculated",
		"🌀 Chaotic mood! Random chaos!",
		"🧠 Smart mood... thinking strategically",
		"🦅 Eagle mood... watching from above",
		"🐺 Wolf mood... hunting in packs",
		"🦁 Lion mood... king of the jungle",
		"🐉 Dragon mood... ancient power",
		"👻 Ghost mood... silent and unseen",
		"🕵️ Spy mode... stealth mode",
		"👑 Royal mood... commanding presence",
		"🎭 Dramatic mood... full of emotions",
		"🤖 Robot mood... precise and efficient",
		"🧙‍♂️ Wizard mood... magical powers",
	}

	moodIndex := (dayOfMonth - 1) % len(moods)
	selectedMood := moods[moodIndex]

	for _, char := range selectedMood {
		fmt.Printf("%c", char)
		time.Sleep(30 * time.Millisecond)
	}

	fmt.Println("\n")
	fmt.Println()
}

func printStaticBanner() {
	banner := `
      M I N O T A U R   D E B U G

`
	fmt.Print(banner)
}

func printUsage() {
	fmt.Println("Minotaur The twin Credential Tester by @m3k4labs")
	fmt.Println("------------------------------------------------")
	fmt.Println()
	fmt.Println("# USAGE EXAMPLE:")
	fmt.Println("  minotaur -t TARGETS -u USERS -p PASSWORDS --[Protocol] [Options]")
	fmt.Println("  minotaur -t target.txt -p pass.txt -u user.txt --ssh -th=100 -m=2 -dr=5 -c=5 --ram=2GB")
	fmt.Println("  minotaur -L=admin -P=admin -T=192.168.1.1/24 --ssh --port=2222")
	fmt.Println()
	fmt.Println("# REQUIRED (single letter flags):")
	fmt.Println("  -u FILE, -U= username   : File containing usernames/single user")
	fmt.Println("  -p FILE, -P= password   : File containing passwords/single password")
	fmt.Println("  -t FILE, -T= target     : File containing target/single target")
	fmt.Println("                            Supports: single IP, CIDR (192.168.1.0/24),")
	fmt.Println("                            range (192.168.1.1-100), comma-separated")
	fmt.Println("  -o, --output FILE       : Output CSV file (default: results.csv)")
	fmt.Println()
	fmt.Println("# PROTOCOL SELECTION (choose one or more):")
	fmt.Println("  --ssh                   : Enable SSH testing (default port: 22)")
	fmt.Println("  --ftp                   : Enable FTP testing (default port: 21)")
	fmt.Println("  --telnet                : Enable Telnet testing (default port: 23)")
	fmt.Println("  --port=PORT             : Custom port for ALL enabled protocols")
	fmt.Println()
	fmt.Println("# CONFIGURATION:")
	fmt.Println("  --threads=NUM, -th=NUM              : Max persistent workers (default: 50)")
	fmt.Println("  --max-per-host=NUM, -m=NUM          : Max concurrent tasks per host (default: 2)")
	fmt.Println("  --delay=SECONDS, -d=SECONDS         : Base delay between tasks (default: 3.0)")
	fmt.Println("  --delay-retry=SECONDS, -dr=SECONDS  : Delay for local retries (default: 3.0)")
	fmt.Println("  --retries=NUM, -r=NUM               : Max local retries per credential (default: 3)")
	fmt.Println("  --consecutive-fn=NUM, -c=NUM        : Max consecutive false negatives (default: 4)")
	fmt.Println("  --total-fn=NUM, -tt=NUM             : Max total false negatives (default: 10)")
	fmt.Println("  --exponential, -ex=                 : Exponential backoff for retry delay (default: true)")
	fmt.Println("  --timeout=SECONDS, -to=SECONDS      : Connection timeout (default: 3.0)")
	fmt.Println("  --debug, -dbg                       : Enable debug logging (default: false)")
	fmt.Println("  --no-resume, -nr                    : Disable auto-resume (start fresh)")
	fmt.Println("  --force-resume, -fr                 : Force resume even if config changed")
	fmt.Println("  --ram=SIZE                          : RAM limit (e.g. 2GB, 512MB, default: 0)")
	fmt.Println("  --mute                              : Disable configuration & reporting view")
	fmt.Println("  --command=CMD, -cmd=CMD             : Command to execute after successful authentication")
	fmt.Println("  --script=FILE, -sc=FILE             : External script to execute minotaur")
	fmt.Println("                                        Example: --script=./proxy-wrapper.sh")
	fmt.Println("                                                 --script=./automation.py")
	fmt.Println()
	fmt.Println("# NOTES:")
	fmt.Println("  - Auto-resume is enabled by default")
	fmt.Println("  - Multiple protocols can be tested simultaneously --ssh --ftp")
	fmt.Println("  - Ram limit effective for 6 million tasks above")
	fmt.Println("  - Workers are dedicated perhost, no stealing mechanism")
	fmt.Println("  - You can easily stop the scan and continue with a different configuration ")
	fmt.Println("  - Script can modify arguments, environment, or chain multiple runs")
}
// }}}
// {{{ SECTION 14: MEMORY REPORTING
func getMemoryStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"total_os_memory":    m.Sys,
		"heap_allocated":     m.HeapAlloc,
		"heap_in_use":        m.HeapInuse,
		"stack_in_use":       m.StackInuse,
		"goroutines":         runtime.NumGoroutine(),
		"gc_cycles":          m.NumGC,
		"next_gc_target":     m.NextGC,
		"last_gc_time":       m.LastGC,
		"garbage_collected":  m.TotalAlloc - m.HeapAlloc,
	}
}

func printMemoryReport(mute bool) {
	if mute {
		return
	}

	memStats := getMemoryStats()

	fmt.Println("\n" + HeaderInfo("Memory Usage Report:"))
	fmt.Println(TreeBranch() + " " + ("Total OS Memory: ") +
		FormatConfigNumber(formatBytes(int64(memStats["total_os_memory"].(uint64)))))
	fmt.Println(TreeBranch() + " " + ("Heap Allocated: ") +
		FormatConfigNumber(formatBytes(int64(memStats["heap_allocated"].(uint64)))))
	fmt.Println(TreeBranch() + " " + ("Heap In Use: ") +
		FormatConfigNumber(formatBytes(int64(memStats["heap_in_use"].(uint64)))))
	fmt.Println(TreeBranch() + " " + ("Stack In Use: ") +
		FormatConfigNumber(formatBytes(int64(memStats["stack_in_use"].(uint64)))))
	fmt.Println(TreeBranch() + " " + ("Active Goroutines: ") +
		FormatConfigNumber(memStats["goroutines"]))
	fmt.Println(TreeBranch() + " " + ("GC Cycles: ") +
		FormatConfigNumber(memStats["gc_cycles"]))

	if memStats["gc_cycles"].(uint32) > 0 {
		gcEfficiency := float64(memStats["garbage_collected"].(uint64)) /
			float64(memStats["total_os_memory"].(uint64)) * 100
		fmt.Println(TreeBranch() + " " + ("GC Efficiency: ") +
			FormatConfigNumber(fmt.Sprintf("%.1f%%", gcEfficiency)))
	}

	fmt.Println(TreeEnd() + " " + ("Next GC Target: ") +
		FormatConfigNumber(formatBytes(int64(memStats["next_gc_target"].(uint64)))))
}

func printMemoryDebug(debug bool, prefix string) {
	if !debug {
		return
	}

	memStats := getMemoryStats()

	debugLog(true, prefix,
		"Memory: Heap=%s, Sys=%s, Goroutines=%d, GC=%d",
		formatBytes(int64(memStats["heap_allocated"].(uint64))),
		formatBytes(int64(memStats["total_os_memory"].(uint64))),
		memStats["goroutines"],
		memStats["gc_cycles"])
}
// }}}
// {{{ SECTION 15: MAIN & CLI
func main() {
	var config Config
	var sshEnabled, ftpEnabled, telnetEnabled bool
	var customPort int
	var ramLimitStr string
	var scriptPath string

	var singleUser, singlePass, singleTarget string

	flag.StringVar(&config.TargetsFile, "t", "", "File containing target hosts (one per line)")
	flag.StringVar(&config.UsersFile, "u", "", "File containing usernames (one per line)")
	flag.StringVar(&config.PasswordsFile, "p", "", "File containing passwords (one per line)")
	flag.StringVar(&singleUser, "U", "", "Single username (alternative to -u FILE)")
	flag.StringVar(&singlePass, "P", "", "Single password (alternative to -p FILE)")
	flag.StringVar(&singleTarget, "T", "", "Single target or range/subnet (alternative to -t FILE)")
    flag.BoolVar(&config.Mute, "mute", false, "Mute configuration output (show only banner and progress)")
	flag.StringVar(&config.OutputFile, "o", "results.csv", "Output CSV file")
	flag.StringVar(&config.OutputFile, "output", "results.csv", "Output CSV file")
	flag.StringVar(&config.Command, "command", "", "Command to execute after successful SSH/Telnet authentication")
	flag.StringVar(&config.Command, "cmd", "", "Command to execute after successful SSH/Telnet authentication (alias)")
	flag.StringVar(&ramLimitStr, "ram", "0", "RAM limit for batching (e.g., 2GB, 512MB, 0=unlimited)")
	flag.StringVar(&scriptPath, "script", "", "External script to execute minotaur")
	flag.StringVar(&scriptPath, "sc", "", "External script to execute minotaur")
	flag.BoolVar(&sshEnabled, "ssh", false, "Enable SSH testing")
	flag.BoolVar(&ftpEnabled, "ftp", false, "Enable FTP testing")
	flag.BoolVar(&telnetEnabled, "telnet", false, "Enable Telnet testing")
	flag.IntVar(&customPort, "port", 0, "Custom port for ALL enabled protocols (overrides defaults)")
	flag.IntVar(&config.MaxThreads, "th", 50, "Max persistent workers")
	flag.IntVar(&config.MaxThreads, "threads", 50, "Max persistent workers")
	flag.IntVar(&config.MaxPerHost, "m", 1, "Max concurrent tasks per host")
	flag.IntVar(&config.MaxPerHost, "max-per-host", 1, "Max concurrent tasks per host")
	flag.Float64Var(&config.BaseDelay, "d", 3.0, "Base delay between tasks (seconds)")
	flag.Float64Var(&config.BaseDelay, "delay", 3.0, "Base delay between tasks (seconds)")
	flag.Float64Var(&config.RetryDelay, "dr", 3.0, "Delay for local retries (seconds)")
	flag.Float64Var(&config.RetryDelay, "delay-retry", 3.0, "Delay for local retries (seconds)")
	flag.IntVar(&config.MaxRetries, "r", 3, "Max local retries per credential")
	flag.IntVar(&config.MaxRetries, "retries", 3, "Max local retries per credential")
	flag.IntVar(&config.MaxConsecutiveFN, "c", 4, "Max consecutive false negatives")
	flag.IntVar(&config.MaxConsecutiveFN, "consecutive-fn", 4, "Max consecutive false negatives")
	flag.IntVar(&config.MaxTotalFN, "tt", 10, "Max total false negatives")
	flag.IntVar(&config.MaxTotalFN, "total-fn", 10, "Max total false negatives")
	flag.BoolVar(&config.ExponentialBackoff, "ex", true, "Enable exponential backoff for retry delay")
	flag.BoolVar(&config.ExponentialBackoff, "exponential", true, "Enable exponential backoff for retry delay")
	flag.Float64Var(&config.Timeout, "to", 3.0, "Connection timeout (seconds)")
	flag.Float64Var(&config.Timeout, "timeout", 3.0, "Connection timeout (seconds)")
	flag.BoolVar(&config.Debug, "dbg", false, "Enable debug logging")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&config.NoResume, "nr", false, "Disable auto-resume (start fresh)")
	flag.BoolVar(&config.NoResume, "no-resume", false, "Disable auto-resume (start fresh)")
	flag.BoolVar(&config.ForceResume, "fr", false, "Force resume even if config changed")
	flag.BoolVar(&config.ForceResume, "force-resume", false, "Force resume even if config changed")

	flag.Usage = printUsage
	flag.Parse()

	if singleUser != "" {
		tmpUserFile, err := CreateTempFileWithContent(singleUser)
		if err != nil {
			fmt.Printf("Error creating temp user file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmpUserFile)
		config.UsersFile = tmpUserFile
	}

	if singlePass != "" {
		tmpPassFile, err := CreateTempFileWithContent(singlePass)
		if err != nil {
			fmt.Printf("Error creating temp password file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmpPassFile)
		config.PasswordsFile = tmpPassFile
	}

	if singleTarget != "" {
		targets, err := ParseTargetRange(singleTarget)
		if err != nil {
			fmt.Printf("Error parsing target range: %v\n", err)
			os.Exit(1)
		}

		tmpTargetFile, err := CreateTempFileWithLines(targets)
		if err != nil {
			fmt.Printf("Error creating temp target file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmpTargetFile)
		config.TargetsFile = tmpTargetFile
	}

	if config.UsersFile == "" && singleUser == "" {
		fmt.Println("Error: either -u FILE or -L USERNAME must be specified")
		printUsage()
		os.Exit(1)
	}

	if config.PasswordsFile == "" && singlePass == "" {
		fmt.Println("Error: either -p FILE or -P PASSWORD must be specified")
		printUsage()
		os.Exit(1)
	}

	if config.TargetsFile == "" && singleTarget == "" {
		fmt.Println("Error: either -t FILE or -T TARGET must be specified")
		printUsage()
		os.Exit(1)
	}

	if scriptPath != "" {
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			fmt.Printf("Error: script file does not exist: %s\n", scriptPath)
			os.Exit(1)
		}
		if fi, err := os.Stat(scriptPath); err == nil {
			if fi.Mode()&0111 == 0 {
				fmt.Printf("Warning: script %s is not executable\n", scriptPath)
			}
		}
	}

	if ramLimitStr == "0" || ramLimitStr == "" {
		config.RAMLimitBytes = 0
	} else {
		ramLimitBytes, err := parseRAMLimit(ramLimitStr)
		if err != nil {
			fmt.Printf("Error parsing RAM limit: %v\n", err)
			os.Exit(1)
		}
		config.RAMLimitBytes = ramLimitBytes
	}

	if config.Command != "" {
		hasSupportedProtocol := false
		for _, proto := range config.Protocols {
			if (proto.Name == "ssh" || proto.Name == "telnet") && proto.Enabled {
				hasSupportedProtocol = true
				break
			}
		}
		if !hasSupportedProtocol {
			fmt.Println("[WARNING] --command flag is set but SSH/Telnet not enabled")
		}
	}

	config.Protocols = []ProtocolConfig{}

	sshPort := 22
	ftpPort := 21
	telnetPort := 23

	if customPort > 0 && customPort <= 65535 {
		sshPort = customPort
		ftpPort = customPort
		telnetPort = customPort
	}

	if sshEnabled {
		config.Protocols = append(config.Protocols, ProtocolConfig{
			Name:    "ssh",
			Port:    sshPort,
			Enabled: true,
		})
	}

	if ftpEnabled {
		config.Protocols = append(config.Protocols, ProtocolConfig{
			Name:    "ftp",
			Port:    ftpPort,
			Enabled: true,
		})
	}

	if telnetEnabled {
		config.Protocols = append(config.Protocols, ProtocolConfig{
			Name:    "telnet",
			Port:    telnetPort,
			Enabled: true,
		})
	}

	if len(config.Protocols) == 0 {
		fmt.Println("Error: at least one protocol must be specified (--ssh, --ftp, or --telnet)")
		printUsage()
		os.Exit(1)
	}

	if singleUser == "" {
		if _, err := os.Stat(config.UsersFile); os.IsNotExist(err) {
			fmt.Printf("Error: file does not exist: %s\n", config.UsersFile)
			os.Exit(1)
		}
	}

	if singlePass == "" {
		if _, err := os.Stat(config.PasswordsFile); os.IsNotExist(err) {
			fmt.Printf("Error: file does not exist: %s\n", config.PasswordsFile)
			os.Exit(1)
		}
	}

	if singleTarget == "" {
		if _, err := os.Stat(config.TargetsFile); os.IsNotExist(err) {
			fmt.Printf("Error: file does not exist: %s\n", config.TargetsFile)
			os.Exit(1)
		}
	}

	if config.Timeout <= 0 {
		fmt.Println("[!] Warning: Timeout must be > 0. Setting to 1.0 second")
		config.Timeout = 1.0
	}

	scriptExecutor := NewScriptExecutor(scriptPath, config.Debug)

	if scriptExecutor.ShouldExit() {
		debugLog(config.Debug, "MAIN", "Executing via script: %s", scriptPath)

		if err := scriptExecutor.Execute(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	if !config.Debug {
		printAnimatedBanner()
	} else {
		printStaticBanner()
	}

	if !config.Mute {
		fmt.Println(HeaderPlus("Configuration: ") + Magenta("Persistent labyrinth pool"))
		if config.RAMLimitBytes > 0 {
			fmt.Println(TreeBranch() + " " + ("Batching: ") + Magenta("True"))
			fmt.Println(TreeBranch() + " " + ("RAM limit: ") + formatBytes(config.RAMLimitBytes))
		} else {
			fmt.Println(TreeBranch() + " " + ("RAM limit: ") + Magenta("Unlimited"))
			fmt.Println(TreeBranch() + " " + ("Batching: ") + Magenta("False"))
		}

		if config.NoResume {
			fmt.Println(TreeBranch() + " " + ("Auto-resume: ") + Magenta("False"))
		} else {
			fmt.Println(TreeBranch() + " " + ("Auto-resume: ") + Magenta("True"))
			if config.ForceResume {
				fmt.Println(TreeBranch() + " " + ("Force resume: ") + Magenta("True"))
			}
		}

		if singleUser != "" || singlePass != "" || singleTarget != "" {
			if singleUser != "" {
				fmt.Println(TreeBranch() + " " + ("Username: ") + Magenta(singleUser))
			}
			if singlePass != "" {
				fmt.Println(TreeBranch() + " " + ("Password: ") + Magenta(singlePass))
			}
			if singleTarget != "" {
				fmt.Println(TreeBranch() + " " + ("Target: ") + Magenta(singleTarget))
			}
		}

		if config.Command != "" {
			fmt.Println(TreeBranch() + " " + ("Post-auth command: ") + Magenta(config.Command))
		}

		if scriptPath != "" {
			fmt.Println(TreeBranch() + " " + ("Execution script: ") + Magenta(scriptPath))
		}

		for _, proto := range config.Protocols {
			portInfo := fmt.Sprintf("%d", proto.Port)
			if customPort > 0 {
				portInfo += " (custom)"
			}
			fmt.Println(TreeBranch() + " " + (strings.ToUpper(proto.Name)) + " Port: " +
				FormatConfigNumber(portInfo))
		}

		fmt.Println(TreeBranch() + " " + ("Threads: ") + FormatConfigNumber(config.MaxThreads))
		fmt.Println(TreeBranch() + " " + ("Max concurrent per host: ") + FormatConfigNumber(config.MaxPerHost))
		fmt.Println(TreeBranch() + " " + ("Base delay: ") + FormatConfigNumber(config.BaseDelay))
		fmt.Println(TreeBranch() + " " + ("Local retry delay: ") + FormatConfigNumber(config.RetryDelay))
		fmt.Println(TreeBranch() + " " + ("Max local retries: ") + FormatConfigNumber(config.MaxRetries))
		fmt.Println(TreeBranch() + " " + ("Max consecutive false negatives: ") + FormatConfigNumber(config.MaxConsecutiveFN))
		fmt.Println(TreeEnd() + " " + ("Max total false negatives: ") + FormatConfigNumber(config.MaxTotalFN))
	}

	engine := NewEngine(&config)
	start := time.Now()
	if err := engine.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if !config.Mute {
		elapsed := time.Since(start).Seconds()
		fmt.Print("\n" + HeaderPlus("Total time: ") + FormatConfigNumber(elapsed) + Cyan(" seconds\n"))
		if elapsed > 0 {
			tasksPerSecond := float64(engine.totalTasks) / elapsed
			fmt.Print(HeaderPlus("Throughput: ") + FormatConfigNumber(tasksPerSecond) + Cyan(" tasks/second\n"))
		}
	}
}
// protocol tester
type ProtocolTester interface {
	Test(target string, port int, username, password string) (status string, latency float64, errorMsg string)
}
// }}}
