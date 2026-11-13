package main

// 内嵌 Web 界面：IP / 端口 两个输入框（都支持多行、多值）+ 提交扫描。
//
// 扫描在后台作业里按批推进（默认每批 512 个地址），页面轮询进度，因此
// 一次提交上万个地址也不会被"上限"挡住，也不会因为单个 HTTP 请求过长而超时。
// 只依赖标准库；默认只监听 127.0.0.1。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"goport/internal/enc"
	"goport/internal/npcap"
	"goport/internal/scan"
)

const (
	// webBatchHosts 是每个批次处理的地址数：按批推进既能报告进度，也能让每批
	// 结束后释放探针表/句柄，避免一次性压上几十万探针。
	webBatchHosts = 512
	// webMaxResults 是内存中保留的结果行上限（超出只计数、不再保留）。
	webMaxResults   = 200_000
	webMaxBodyBytes = 1 << 20
	// webMinBatchBudget 是单批至少给的时间预算，避免小批次被估算得太紧。
	webMinBatchBudget = 120 * time.Second
	// webJobHistory 是内存里保留的历史作业数（供导出/回看）。
	webJobHistory = 8
)

// scanRequest 是 /api/scan 与 /api/preview 的请求体。
type scanRequest struct {
	Target string `json:"target"`
	Ports  string `json:"ports"`
	Mode   string `json:"mode"`
	Banner bool   `json:"banner"`
	All    bool   `json:"all"` // 显示 closed / filtered（默认只看 open）
}

type scanStats struct {
	Open     uint64  `json:"open"`
	Closed   uint64  `json:"closed"`
	Filtered uint64  `json:"filtered"`
	Sent     uint64  `json:"sent"`
	PPS      float64 `json:"pps"`
}

// previewResponse 是 /api/preview 的响应体：只解析，不扫描。
type previewResponse struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Targets  int    `json:"targets"`
	Ports    int    `json:"ports"`
	TCPPorts int    `json:"tcp_ports"`
	UDPPorts int    `json:"udp_ports"`
	Pairs    int    `json:"pairs"`
	Batches  int    `json:"batches"`
}

// startResponse 是 /api/scan 的响应体（作业已创建，立即返回）。
type startResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	ID      string `json:"id"`
	Targets int    `json:"targets"`
	Ports   int    `json:"ports"`
	Pairs   int    `json:"pairs"`
	Batches int    `json:"batches"`
}

// statusResponse 是 /api/status 的响应体。
type statusResponse struct {
	OK          bool      `json:"ok"`
	Error       string    `json:"error,omitempty"`
	ID          string    `json:"id"`
	Running     bool      `json:"running"`
	Mode        string    `json:"mode"`
	Targets     int       `json:"targets"`
	Ports       int       `json:"ports"`
	Pairs       int       `json:"pairs"`
	Done        uint64    `json:"done"`
	Percent     float64   `json:"percent"`
	ElapsedMS   int64     `json:"elapsed_ms"`
	ETAMS       int64     `json:"eta_ms"`
	Batch       int       `json:"batch"`
	Batches     int       `json:"batches"`
	Stats       scanStats `json:"stats"`
	ResultCount int       `json:"result_count"`
	Truncated   bool      `json:"truncated,omitempty"`
	Target      string    `json:"target"`
	PortsSpec   string    `json:"ports_spec"`
}

// resultsResponse 是 /api/results 的响应体。
type resultsResponse struct {
	OK        bool          `json:"ok"`
	Error     string        `json:"error,omitempty"`
	ID        string        `json:"id"`
	Running   bool          `json:"running"`
	Results   []scan.Result `json:"results"`
	Truncated bool          `json:"truncated,omitempty"`
}

// ---- 作业 --------------------------------------------------------------

// job 是一次扫描作业：按批执行、累计结果、对外提供进度快照。
type job struct {
	id      string
	mu      sync.Mutex
	started time.Time
	ended   time.Time

	target    string
	portSpec  string
	requested scan.Mode
	mode      scan.Mode

	hosts   int
	ports   int
	pairs   int
	batches int
	batch   int

	baseDone uint64 // 已结束批次的探针数
	done     uint64 // 含当前批次的进度
	stats    scanStats

	results   []scan.Result
	truncated bool
	running   bool
	err       string

	cancel context.CancelFunc
}

func newJob(target, portSpec string, mode scan.Mode, hosts, ports, batches int) *job {
	return &job{
		id:        newJobID(),
		started:   time.Now(),
		target:    target,
		portSpec:  portSpec,
		requested: mode,
		mode:      mode,
		hosts:     hosts,
		ports:     ports,
		pairs:     hosts * ports,
		batches:   batches,
		running:   true,
	}
}

func newJobID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// addResult 由扫描引擎的回调调用（可能并发）。
func (j *job) addResult(r scan.Result) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.results) < webMaxResults {
		r.RTTMs = float64(r.RTT.Microseconds()) / 1000.0
		r.At = time.Now().Format(time.RFC3339)
		j.results = append(j.results, r)
	} else {
		j.truncated = true
	}
}

// setProgress 把一个批次的进度映射到整体进度。
func (j *job) setProgress(s scan.Stats) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = j.baseDone + s.Done
}

// mergeBatch 累计一批结束后的统计。
func (j *job) mergeBatch(s scan.Stats) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.stats.Open += s.Open
	j.stats.Closed += s.Closed
	j.stats.Filtered += s.Filtered
	j.stats.Sent += s.Sent
	if s.PPS > 0 {
		j.stats.PPS = s.PPS
	}
	j.baseDone += s.Probes
	j.done = j.baseDone
	j.batch++
}

func (j *job) setMode(m scan.Mode) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if m != "" {
		j.mode = m
	}
}

func (j *job) finish(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.running = false
	j.ended = time.Now()
	if err != nil {
		j.err = err.Error()
	}
}

func (j *job) cancelled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return !j.running
}

func (j *job) status() statusResponse {
	j.mu.Lock()
	defer j.mu.Unlock()
	elapsed := time.Since(j.started)
	if !j.running && !j.ended.IsZero() {
		elapsed = j.ended.Sub(j.started)
	}
	pct := 0.0
	if j.pairs > 0 {
		pct = 100 * float64(j.done) / float64(j.pairs)
		if pct > 100 {
			pct = 100
		}
	}
	eta := int64(0)
	if j.running && pct > 1 && pct < 100 {
		eta = int64(float64(elapsed.Milliseconds()) * (100 - pct) / pct)
	}
	return statusResponse{
		OK:          j.err == "",
		Error:       j.err,
		ID:          j.id,
		Running:     j.running,
		Mode:        string(j.mode),
		Targets:     j.hosts,
		Ports:       j.ports,
		Pairs:       j.pairs,
		Done:        j.done,
		Percent:     pct,
		ElapsedMS:   elapsed.Milliseconds(),
		ETAMS:       eta,
		Batch:       j.batch,
		Batches:     j.batches,
		Stats:       j.stats,
		ResultCount: len(j.results),
		Truncated:   j.truncated,
		Target:      j.target,
		PortsSpec:   j.portSpec,
	}
}

func (j *job) snapshotResults() ([]scan.Result, bool, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]scan.Result, len(j.results))
	copy(out, j.results)
	return out, j.running, j.truncated
}

// ---- 服务 --------------------------------------------------------------

// webServer 管理作业：同一时刻只跑一个扫描，历史作业保留少量用于导出。
type webServer struct {
	logf func(string, ...any)

	busy   atomic.Bool
	jobsMu sync.Mutex
	jobs   map[string]*job
	order  []string
	lastID string
	synOK  atomic.Int32
}

func newWebHandler(stderr io.Writer) http.Handler {
	ws := &webServer{
		logf: func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) },
		jobs: make(map[string]*job),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, indexHTML)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/preview", ws.handlePreview)
	mux.HandleFunc("/api/scan", ws.handleStart)
	mux.HandleFunc("/api/status", ws.handleStatus)
	mux.HandleFunc("/api/results", ws.handleResults)
	mux.HandleFunc("/api/cancel", ws.handleCancel)
	mux.HandleFunc("/api/export", ws.handleExport)
	return mux
}

// handlePreview 解析目标与端口并返回数量（不扫描）。
func (ws *webServer) handlePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, previewResponse{Error: "只接受 POST"})
		return
	}
	body := http.MaxBytesReader(w, r.Body, webMaxBodyBytes)
	var req scanRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, previewResponse{Error: "请求格式错误：" + err.Error()})
		return
	}
	addrs, ports, err := parseScope(req.Target, req.Ports)
	if err != nil {
		writeJSON(w, http.StatusOK, previewResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, previewResponse{
		OK:       true,
		Targets:  len(addrs),
		Ports:    ports.Total(),
		TCPPorts: len(ports.TCP),
		UDPPorts: len(ports.UDP),
		Pairs:    len(addrs) * ports.Total(),
		Batches:  batchCount(len(addrs)),
	})
}

// handleStart 创建扫描作业并立即返回作业 id，扫描在后台按批推进。
func (ws *webServer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, startResponse{Error: "只接受 POST"})
		return
	}
	body := http.MaxBytesReader(w, r.Body, webMaxBodyBytes)
	var req scanRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, startResponse{Error: "请求格式错误：" + err.Error()})
		return
	}
	addrs, ports, err := parseScope(req.Target, req.Ports)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, startResponse{Error: err.Error()})
		return
	}
	mode, err := scan.ParseMode(req.Mode)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, startResponse{Error: err.Error()})
		return
	}
	if !ws.busy.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, startResponse{Error: "上一个扫描还没结束，请等它完成或先点「停止」"})
		return
	}

	j := newJob(req.Target, req.Ports, mode, len(addrs), ports.Total(), batchCount(len(addrs)))
	ws.register(j)
	go ws.runJob(j, addrs, ports, req)

	writeJSON(w, http.StatusOK, startResponse{
		OK:      true,
		ID:      j.id,
		Targets: j.hosts,
		Ports:   j.ports,
		Pairs:   j.pairs,
		Batches: j.batches,
	})
}

func (ws *webServer) register(j *job) {
	ws.jobsMu.Lock()
	defer ws.jobsMu.Unlock()
	ws.jobs[j.id] = j
	ws.order = append(ws.order, j.id)
	ws.lastID = j.id
	for len(ws.order) > webJobHistory {
		old := ws.order[0]
		ws.order = ws.order[1:]
		delete(ws.jobs, old)
	}
}

func (ws *webServer) lookup(id string) *job {
	ws.jobsMu.Lock()
	defer ws.jobsMu.Unlock()
	if id == "" {
		id = ws.lastID
	}
	return ws.jobs[id]
}

// runJob 按批执行整个扫描。
func (ws *webServer) runJob(j *job, addrs []uint32, ports scan.PortSet, req scanRequest) {
	defer ws.busy.Store(false)

	ctx, cancel := context.WithCancel(context.Background())
	j.mu.Lock()
	j.cancel = cancel
	j.mu.Unlock()
	defer cancel()

	batchSize := webBatchHosts
	for start := 0; start < len(addrs); start += batchSize {
		if ctx.Err() != nil {
			j.finish(nil)
			return
		}
		end := start + batchSize
		if end > len(addrs) {
			end = len(addrs)
		}
		sub := addrs[start:end]

		// 第一批可能是 auto（会尝试 SYN）；之后直接用已经确定的模式，避免重复探测。
		mode := j.requested
		j.mu.Lock()
		if j.batch > 0 && j.mode != "" {
			mode = j.mode
		}
		j.mu.Unlock()

		cfg := &scan.Config{
			Scope:             &scan.Scope{Addrs: sub, Ports: ports},
			Mode:              mode,
			Rate:              2000,
			Timeout:           600 * time.Millisecond,
			Retries:           1,
			Banner:            req.Banner,
			BannerConcurrency: 32,
			BannerTimeout:     1000 * time.Millisecond,
			Concurrency:       300,
			ShowClosed:        req.All,
			ShowFiltered:      req.All,
			Warnf: func(format string, a ...any) {
				ws.logf("[web] "+format, a...)
			},
			Progress: func(s scan.Stats) { j.setProgress(s) },
		}

		// 单批时间预算：按探测数 ×(1+重试)/速率 估算，再给 3 倍余量。
		probes := len(sub) * ports.Total()
		budget := time.Duration(float64(probes*(cfg.Retries+1)) / float64(cfg.Rate) * 3 * float64(time.Second))
		if budget < webMinBatchBudget {
			budget = webMinBatchBudget
		}
		bctx, bcancel := context.WithTimeout(ctx, budget)

		stats, err := scan.Run(bctx, cfg, j.addResult)
		bcancel()
		j.setMode(cfg.UsedMode)
		j.mergeBatch(stats)

		if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			j.finish(err)
			return
		}
	}
	j.finish(nil)
}

// handleStatus 返回作业进度。
func (ws *webServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	j := ws.lookup(r.URL.Query().Get("id"))
	if j == nil {
		writeJSON(w, http.StatusNotFound, statusResponse{Error: "找不到该扫描作业"})
		return
	}
	writeJSON(w, http.StatusOK, j.status())
}

// handleResults 返回作业已收集到的结果（扫描中也可以取部分结果）。
func (ws *webServer) handleResults(w http.ResponseWriter, r *http.Request) {
	j := ws.lookup(r.URL.Query().Get("id"))
	if j == nil {
		writeJSON(w, http.StatusNotFound, resultsResponse{Error: "找不到该扫描作业"})
		return
	}
	list, running, truncated := j.snapshotResults()
	writeJSON(w, http.StatusOK, resultsResponse{
		OK: true, ID: j.id, Running: running, Results: list, Truncated: truncated,
	})
}

// handleCancel 请求停止作业。
func (ws *webServer) handleCancel(w http.ResponseWriter, r *http.Request) {
	j := ws.lookup(r.URL.Query().Get("id"))
	if j == nil {
		writeJSON(w, http.StatusNotFound, statusResponse{Error: "找不到该扫描作业"})
		return
	}
	j.mu.Lock()
	cancel := j.cancel
	j.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, http.StatusOK, j.status())
}

// handleExport 把作业结果导出成 CSV（默认 GB2312/GBK）。
func (ws *webServer) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "只接受 GET / POST", http.StatusMethodNotAllowed)
		return
	}
	j := ws.lookup(r.URL.Query().Get("id"))
	if j == nil {
		http.Error(w, "还没有扫描记录：请先提交一次扫描再导出。", http.StatusNotFound)
		return
	}
	list, _, truncated := j.snapshotResults()
	if len(list) == 0 {
		http.Error(w, "这次扫描没有结果可导出。", http.StatusNotFound)
		return
	}
	st := j.status()

	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.UseCRLF = true // Excel 更认 CRLF
	_ = cw.Write([]string{"时间", "主机", "端口", "协议", "状态", "服务", "耗时(ms)", "信息"})
	for _, res := range list {
		rtt := ""
		if res.RTT > 0 {
			rtt = strconv.FormatFloat(res.RTTMs, 'f', 2, 64)
		}
		_ = cw.Write([]string{
			formatCSVTime(res.At, j.started), res.Host, strconv.Itoa(int(res.Port)),
			res.Proto, res.State, res.Service, rtt, res.Banner,
		})
	}
	if truncated {
		_ = cw.Write([]string{"# 结果过多，仅导出前 " + strconv.Itoa(len(list)) + " 条", "", "", "", "", "", "", ""})
	}
	cw.Flush()

	data := buf.Bytes()
	contentType := "text/csv; charset=utf-8"
	if !strings.EqualFold(r.URL.Query().Get("enc"), "utf8") {
		if gbk, err := enc.ToGBK(string(data)); err != nil {
			ws.logf("[web] GBK 转换失败，改发 UTF-8：%v", err)
		} else {
			data = gbk
			contentType = "text/csv; charset=gbk"
		}
	}

	name := fmt.Sprintf("goport-%s-%s.csv", safeFileName(st.Target), j.started.Format("20060102-150405"))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// formatCSVTime 把结果里的 RFC3339 时间改写成 Excel 友好的格式。
func formatCSVTime(at string, fallback time.Time) string {
	if at != "" {
		if t, err := time.Parse(time.RFC3339, at); err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
		return at
	}
	return fallback.Format("2006-01-02 15:04:05")
}

// safeFileName 把目标表达式压成适合放进文件名的片段。
func safeFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		case r == '/' || r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t':
			b.WriteByte('_')
		}
		if b.Len() >= 40 {
			break
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "scan"
	}
	return out
}

// expandPortSpec 允许把预设名和具体端口混写，例如 "minimal,8080" 或每行一个预设。
func expandPortSpec(spec string) string {
	tokens := strings.FieldsFunc(spec, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\t', '\n', '\r':
			return true
		}
		return false
	})
	if len(tokens) == 0 {
		return ""
	}
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if expanded, ok := scan.LookupPreset(t); ok {
			out = append(out, expanded)
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, ",")
}

// parseScope 把网页输入解析成地址与端口。目标支持多行、逗号、空格分隔，以及
// CIDR / 范围 / 域名；端口支持区间、U: 前缀、预设名（可与具体端口混写）。
//
// 这里不限制地址数量：大批量由 runJob 内部的批次推进处理。
func parseScope(target, portSpec string) ([]uint32, scan.PortSet, error) {
	target = strings.TrimSpace(target)
	portSpec = strings.TrimSpace(portSpec)
	if target == "" {
		return nil, scan.PortSet{}, errors.New("请输入 IP 或网段")
	}
	if portSpec == "" {
		portSpec = "1-1000"
	}
	if strings.ContainsAny(target, `\@`) || strings.HasSuffix(strings.ToLower(target), ".txt") {
		return nil, scan.PortSet{}, errors.New("网页模式不支持文件路径，请直接粘贴 IP（每行一个，或用逗号 / 空格分隔）")
	}

	targeting, err := scan.ParseTargets([]string{target})
	if err != nil {
		return nil, scan.PortSet{}, err
	}
	if len(targeting.Addrs) == 0 {
		return nil, scan.PortSet{}, errors.New("没有解析到任何地址")
	}

	ports, err := scan.ParsePortSpec(expandPortSpec(portSpec))
	if err != nil {
		return nil, scan.PortSet{}, err
	}
	return targeting.Addrs, ports, nil
}

func batchCount(hosts int) int {
	if hosts <= 0 {
		return 0
	}
	n := (hosts + webBatchHosts - 1) / webBatchHosts
	if n == 0 {
		n = 1
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// runDesktop 是"双击启动"的入口：起 Web 界面、自动开浏览器，出错时停住窗口。
func runDesktop(stderr io.Writer) int {
	fmt.Fprintln(stderr, "GoPort 正在启动，请稍候…")
	code := runWeb("127.0.0.1:8080", stderr, true)
	if code != 0 {
		waitForExit(stderr)
	}
	return code
}

// runWeb 启动 Web 界面并阻塞到 Ctrl+C。
//
// 端口被占用时会自动往后找（8080 → 8081 → …），并打印实际使用的地址。
func runWeb(addr string, stderr io.Writer, openBrowser bool) int {
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	ln, listenAddr, err := listenWeb(addr)
	if err != nil {
		fmt.Fprintf(stderr, "无法监听 %s：%v\n", addr, err)
		return 1
	}
	url := "http://" + displayAddr(listenAddr)
	fmt.Fprintf(stderr, "GoPort Web 界面已启动： %s\n", url)
	if listenAddr != addr {
		fmt.Fprintf(stderr, "（%s 已被占用，改用 %s）\n", addr, displayAddr(listenAddr))
	}
	fmt.Fprintln(stderr, "在浏览器里填 IP 与端口，点「提交扫描」；扫完可导出 GBK CSV。")
	fmt.Fprintf(stderr, "扫描按批推进（每批 %d 个地址），大批量也能看到实时进度。\n", webBatchHosts)
	if !npcap.IsElevated() {
		fmt.Fprintln(stderr, "提示：当前不是管理员权限，扫描会自动使用 connect 模式（结果相同，速率略低）。")
	}
	fmt.Fprintln(stderr, "关闭这个窗口或按 Ctrl+C 即可停止。")
	if openBrowser && os.Getenv("GOPORT_NO_BROWSER") == "" {
		if err := openBrowserURL(url); err != nil {
			fmt.Fprintf(stderr, "（自动打开浏览器失败：%v，请手动访问上面的地址）\n", err)
		}
	}

	srv := &http.Server{
		Handler:           newWebHandler(stderr),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "Web 服务异常退出：", err)
		return 1
	}
	fmt.Fprintln(stderr, "已停止。")
	return 0
}

// listenWeb 在 addr 上监听；端口占用时依次尝试后面的端口。
func listenWeb(addr string) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, addr, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, addr, fmt.Errorf("端口 %q 无效", portStr)
	}
	var lastErr error
	for i := 0; i < 11; i++ {
		cand := net.JoinHostPort(host, strconv.Itoa(port+i))
		ln, err := net.Listen("tcp", cand)
		if err == nil {
			return ln, cand, nil
		}
		lastErr = err
	}
	return nil, addr, lastErr
}

// displayAddr 把 0.0.0.0:8080 这类监听地址换成可点击的 127.0.0.1。
func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// indexHTML 是页面本体（单文件，无外部依赖）。
const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GoPort 端口扫描</title>
<style>
  :root {
    --bg: #f5f7fa; --card: #fff; --fg: #161c25; --muted: #6b7280;
    --line: #e5e9f0; --accent: #2c79f7; --ok: #12805c; --warn: #b45309; --bad: #b42318;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 40px 16px; background: var(--bg); color: var(--fg);
    font: 14px/1.6 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
  }
  .wrap { max-width: 960px; margin: 0 auto; }
  header { margin-bottom: 20px; }
  h1 { margin: 0 0 6px; font-size: 22px; letter-spacing: .3px; }
  header p { margin: 0; color: var(--muted); font-size: 13px; }
  .card {
    background: var(--card); border: 1px solid var(--line); border-radius: 12px;
    padding: 20px; box-shadow: 0 1px 2px rgba(16,24,40,.04); margin-bottom: 18px;
  }
  form { display: grid; grid-template-columns: 1fr 1fr auto; gap: 14px; align-items: end; }
  @media (max-width: 680px) { form { grid-template-columns: 1fr; } }
  label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 6px; }
  input, select, textarea {
    width: 100%; padding: 10px 12px; font-size: 14px; color: var(--fg); background: #fff;
    border: 1px solid #cfd6e4; border-radius: 8px; outline: none; transition: border-color .15s, box-shadow .15s;
  }
  textarea {
    resize: vertical; min-height: 84px; line-height: 1.5;
    font-family: ui-monospace, Consolas, "Courier New", monospace; font-size: 13px;
  }
  input:focus, select:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(44,121,247,.15); }
  .row2 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-top: 14px; }
  @media (max-width: 680px) { .row2 { grid-template-columns: 1fr; } }
  .btns { display: flex; gap: 8px; }
  button {
    padding: 10px 22px; font-size: 14px; font-weight: 600; color: #fff; background: var(--accent);
    border: 0; border-radius: 8px; cursor: pointer; white-space: nowrap; height: 40px;
  }
  button:hover { background: #1d68e0; }
  button:disabled { background: #9dbcf5; cursor: not-allowed; }
  button.stop { background: #fff; color: var(--bad); border: 1px solid #f3c3bf; }
  button.stop:hover { background: #fdecea; }
  .hint { color: var(--muted); font-size: 12px; margin-top: 12px; }
  .hint code { background: #eef2f9; padding: 1px 5px; border-radius: 4px; }
  #preview { margin-top: 10px; font-size: 13px; color: var(--muted); }
  #preview.err { color: var(--bad); }
  #status { font-size: 13px; color: var(--muted); min-height: 20px; }
  #status.busy { color: var(--accent); }
  #status.err { color: var(--bad); }
  #progwrap { margin-top: 12px; }
  #bar { height: 8px; background: #e6ecf7; border-radius: 999px; overflow: hidden; }
  #fill { height: 100%; width: 0%; background: var(--accent); transition: width .25s ease; }
  #progtext { margin-top: 6px; font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }
  .stats { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 10px; font-size: 13px; color: var(--muted); }
  .stats b { color: var(--fg); font-weight: 600; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-size: 12px; color: var(--muted); font-weight: 600; background: #fafbfd; }
  tbody tr:hover { background: #f7f9fd; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .open { color: var(--ok); background: #e7f6ef; }
  .closed { color: var(--bad); background: #fdecea; }
  .other { color: var(--warn); background: #fdf3e2; }
  .mono { font-family: ui-monospace, Consolas, monospace; }
  .empty { color: var(--muted); font-size: 13px; padding: 14px 2px; }
  .dl {
    display: inline-block; padding: 8px 16px; margin: 0 10px 0 0; font-size: 13px; font-weight: 600;
    color: #fff; background: var(--ok); border-radius: 8px; text-decoration: none;
  }
  .dl:hover { background: #0e6a4c; }
  .dl.ghost { color: var(--fg); background: #eef2f9; }
  .dl.ghost:hover { background: #e2e8f5; }
  #exportbar { margin-top: 14px; padding-top: 14px; border-top: 1px dashed var(--line); }
  #exportbar .note { color: var(--muted); font-size: 12px; margin-top: 8px; }
  .spinner {
    display: inline-block; width: 12px; height: 12px; margin-right: 6px; vertical-align: -1px;
    border: 2px solid rgba(44,121,247,.25); border-top-color: var(--accent); border-radius: 50%;
    animation: spin .8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>GoPort 端口扫描</h1>
    <p>基于 Npcap 的 SYN 扫描，非管理员权限时自动退回 connect 模式。IP 与端口都支持多值。</p>
  </header>

  <div class="card">
    <form id="form">
      <div>
        <label for="target">IP / 网段（每行一个，也可用逗号 / 空格）</label>
        <textarea id="target" name="target" rows="4" spellcheck="false" placeholder="10.0.0.5
10.0.0.6
192.168.1.0/24
172.16.0.0/22" required></textarea>
      </div>
      <div>
        <label for="ports">端口（多行 / 逗号 / 区间 / 预设）</label>
        <textarea id="ports" name="ports" rows="4" spellcheck="false" placeholder="22,80,443
1-1000
U:161
minimal" required>1-1000</textarea>
      </div>
      <div class="btns">
        <button id="submit" type="submit">提交扫描</button>
        <button id="stop" class="stop" type="button" hidden>停止</button>
      </div>
    </form>
    <div id="preview">输入 IP 与端口后显示预计探测数量。</div>
    <div id="progwrap" hidden>
      <div id="bar"><div id="fill"></div></div>
      <div id="progtext"></div>
    </div>
    <div class="row2">
      <div>
        <label for="mode">扫描模式</label>
        <select id="mode" name="mode">
          <option value="auto" selected>auto（优先 SYN，无权限自动退回 connect）</option>
          <option value="syn">syn（需要管理员）</option>
          <option value="connect">connect（无需管理员）</option>
        </select>
      </div>
      <div>
        <label for="banner">服务识别</label>
        <select id="banner" name="banner">
          <option value="1" selected>开启（抓 Server / 证书 / 首包）</option>
          <option value="0">关闭（更快）</option>
        </select>
      </div>
      <div>
        <label for="all">结果范围</label>
        <select id="all" name="all">
          <option value="0" selected>只看 open</option>
          <option value="1">同时显示 closed / filtered</option>
        </select>
      </div>
    </div>
    <div class="hint">
      端口支持混写：<code>22,80,443</code> <code>1-1000</code> <code>U:161</code> <code>minimal</code> <code>minimal,8080</code>
      &nbsp;|&nbsp; 地址数量不设上限，扫描会按批推进并显示进度。
    </div>
  </div>

  <div class="card">
    <div id="status">等待扫描。</div>
    <div class="stats" id="stats" hidden>
      <span>目标 <b id="s-targets">0</b></span>
      <span>端口 <b id="s-ports">0</b></span>
      <span>批次 <b id="s-batch">0</b></span>
      <span>耗时 <b id="s-elapsed">0</b> ms</span>
      <span>open <b id="s-open">0</b></span>
      <span>closed <b id="s-closed">0</b></span>
      <span>filtered <b id="s-filtered">0</b></span>
    </div>
    <div id="results"></div>
    <div id="exportbar" hidden>
      <a id="dl-gbk" class="dl" href="#" download>导出 CSV（GB2312 / GBK）</a>
      <a id="dl-utf8" class="dl ghost" href="#" download>导出 UTF-8 CSV</a>
      <div class="note">逗号分隔、CRLF 换行；GBK 版本可直接用中文 Windows 的 Excel 打开。</div>
    </div>
  </div>
</div>

<script>
(function () {
  var form = document.getElementById('form');
  var btn = document.getElementById('submit');
  var stopBtn = document.getElementById('stop');
  var statusEl = document.getElementById('status');
  var resultsEl = document.getElementById('results');
  var statsEl = document.getElementById('stats');
  var previewEl = document.getElementById('preview');
  var targetEl = document.getElementById('target');
  var portsEl = document.getElementById('ports');
  var exportBar = document.getElementById('exportbar');
  var progWrap = document.getElementById('progwrap');
  var fillEl = document.getElementById('fill');
  var progText = document.getElementById('progtext');
  var previewTimer = null;
  var pollTimer = null;
  var jobId = null;

  function setStatus(text, cls) {
    statusEl.className = cls || '';
    statusEl.innerHTML = text;
  }
  function num(id, v) { document.getElementById(id).textContent = v; }
  function fmt(n) { return (n || 0).toLocaleString(); }

  function payload() {
    return {
      target: targetEl.value.trim(),
      ports: portsEl.value.trim(),
      mode: document.getElementById('mode').value,
      banner: document.getElementById('banner').value === '1',
      all: document.getElementById('all').value === '1'
    };
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) { return r.json(); });
  }
  function get(url) {
    return fetch(url).then(function (r) { return r.json(); });
  }

  function refreshPreview() {
    var p = payload();
    if (!p.target) {
      previewEl.className = '';
      previewEl.textContent = '输入 IP 与端口后显示预计探测数量。';
      btn.disabled = false;
      return;
    }
    post('/api/preview', p).then(function (d) {
      if (!d.ok) {
        previewEl.className = 'err';
        previewEl.textContent = d.error;
        btn.disabled = true;
        return;
      }
      btn.disabled = false;
      previewEl.className = '';
      previewEl.textContent = '将扫描 ' + fmt(d.targets) + ' 个地址 × ' + fmt(d.ports) + ' 个端口'
        + '（TCP ' + d.tcp_ports + ' / UDP ' + d.udp_ports + '） = '
        + fmt(d.pairs) + ' 个探测，分 ' + d.batches + ' 批执行';
    }).catch(function () {});
  }

  function schedulePreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(refreshPreview, 350);
  }
  targetEl.addEventListener('input', schedulePreview);
  portsEl.addEventListener('input', schedulePreview);
  refreshPreview();

  function renderRows(list) {
    if (!list.length) {
      resultsEl.innerHTML = '<div class="empty">没有开放的端口（默认只显示 open，可在「结果范围」里改成显示全部）。</div>';
      return;
    }
    var esc = function (s) {
      return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };
    var cls = function (st) { return st === 'open' ? 'open' : (st === 'closed' ? 'closed' : 'other'); };
    var rows = list.map(function (r) {
      return '<tr>'
        + '<td class="mono">' + esc(r.host) + '</td>'
        + '<td class="mono">' + esc(r.port) + '</td>'
        + '<td>' + esc(r.proto) + '</td>'
        + '<td><span class="badge ' + cls(r.state) + '">' + esc(r.state) + '</span></td>'
        + '<td>' + esc(r.service || '-') + '</td>'
        + '<td class="mono">' + (r.rtt_ms > 0 ? r.rtt_ms.toFixed(1) + ' ms' : '-') + '</td>'
        + '<td>' + esc(r.banner || '') + '</td>'
        + '</tr>';
    }).join('');
    resultsEl.innerHTML = '<table><thead><tr>'
      + '<th>主机</th><th>端口</th><th>协议</th><th>状态</th><th>服务</th><th>耗时</th><th>信息</th>'
      + '</tr></thead><tbody>' + rows + '</tbody></table>';
  }

  function stopPolling() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
  }

  function poll() {
    if (!jobId) { return; }
    get('/api/status?id=' + encodeURIComponent(jobId)).then(function (d) {
      if (!d.ok && d.error && !d.running) {
        setStatus('扫描失败：' + d.error, 'err');
        finishUp();
        return;
      }
      fillEl.style.width = Math.min(100, d.percent || 0).toFixed(1) + '%';
      var eta = d.eta_ms > 0 ? '，预计剩余 ' + Math.round(d.eta_ms / 1000) + ' s' : '';
      progText.textContent = '进度 ' + (d.percent || 0).toFixed(1) + '%'
        + '（' + fmt(d.done) + ' / ' + fmt(d.pairs) + ' 个探测，第 ' + d.batch + ' / ' + d.batches + ' 批）'
        + eta + '  · 已发现 ' + fmt(d.result_count) + ' 条  · 模式 ' + d.mode;
      num('s-targets', fmt(d.targets));
      num('s-ports', fmt(d.ports));
      num('s-batch', (d.batch || 0) + '/' + (d.batches || 0));
      num('s-elapsed', fmt(d.elapsed_ms));
      num('s-open', fmt(d.stats.open));
      num('s-closed', fmt(d.stats.closed));
      num('s-filtered', fmt(d.stats.filtered));
      statsEl.hidden = false;

      if (d.running) {
        setStatus('<span class="spinner"></span>扫描进行中…', 'busy');
        pollTimer = setTimeout(poll, 700);
        return;
      }
      if (d.error) {
        setStatus('扫描失败：' + d.error, 'err');
        finishUp();
        return;
      }
      setStatus('扫描完成，用时 ' + (d.elapsed_ms / 1000).toFixed(2) + ' s，模式 ' + d.mode
        + '，命中 ' + fmt(d.result_count) + ' 条。'
        + (d.truncated ? '（结果过多，仅保留前 ' + fmt(d.result_count) + ' 条）' : ''));
      loadResults();
      finishUp();
    }).catch(function () {
      pollTimer = setTimeout(poll, 1500); // 网络抖动时稍后重试
    });
  }

  function loadResults() {
    get('/api/results?id=' + encodeURIComponent(jobId)).then(function (d) {
      renderRows(d.results || []);
      var stamp = Date.now();
      document.getElementById('dl-gbk').href = '/api/export?id=' + encodeURIComponent(jobId) + '&enc=gbk&t=' + stamp;
      document.getElementById('dl-utf8').href = '/api/export?id=' + encodeURIComponent(jobId) + '&enc=utf8&t=' + stamp;
      exportBar.hidden = false;
    }).catch(function () {});
  }

  function finishUp() {
    stopPolling();
    btn.disabled = false;
    stopBtn.hidden = true;
  }

  function resetUI() {
    stopPolling();
    jobId = null;
    statsEl.hidden = true;
    resultsEl.innerHTML = '';
    exportBar.hidden = true;
    progWrap.hidden = true;
    fillEl.style.width = '0%';
    progText.textContent = '';
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var p = payload();
    if (!p.target) { setStatus('请输入 IP 或网段。', 'err'); return; }

    resetUI();
    btn.disabled = true;
    stopBtn.hidden = false;
    setStatus('<span class="spinner"></span>正在提交…', 'busy');

    post('/api/scan', p).then(function (d) {
      if (!d.ok) {
        setStatus('无法开始扫描：' + (d.error || '未知错误'), 'err');
        finishUp();
        return;
      }
      jobId = d.id;
      progWrap.hidden = false;
      setStatus('<span class="spinner"></span>扫描进行中…', 'busy');
      poll();
    }).catch(function (e) {
      setStatus('请求失败：' + e.message, 'err');
      finishUp();
    });
  });

  stopBtn.addEventListener('click', function () {
    if (!jobId) { return; }
    stopBtn.disabled = true;
    post('/api/cancel?id=' + encodeURIComponent(jobId)).then(function () {
      setStatus('正在停止…', 'busy');
    }).catch(function () {}).then(function () {
      stopBtn.disabled = false;
    });
  });
})();
</script>
</body>
</html>
`
