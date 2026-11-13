// Command goport is a fast Npcap-based TCP/UDP port scanner for Windows.
//
// It injects stateless TCP SYN frames through Npcap's wpcap.dll (bound from pure
// Go, no cgo) and reads the SYN-ACK/RST replies, in the spirit of Goby's scan
// engine but with a command-line interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"goport/internal/enc"
	"goport/internal/netinfo"
	"goport/internal/npcap"
	"goport/internal/scan"
)

const version = "1.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type options struct {
	targets      stringList
	ports        string
	preset       string
	gobyConfig   string
	iface        string
	mode         string
	rate         int
	timeoutMs    int
	retries      int
	shuffle      bool
	batch        bool
	arpTimeoutMs int
	ttl          int
	srcIP        string
	srcMAC       string
	gwMAC        string
	concurrency  int
	banner       bool
	bannerMs     int
	showClosed   bool
	showFiltered bool
	format       string
	csvEnc       string
	out          string
	verbose      bool
	noColor      bool
	listIf       bool
	doctor       bool
	dryRun       bool
	showVersion  bool
	noProgress   bool
	web          string
	ui           bool
	open         bool
}

func run(args []string, stdout, stderr io.Writer) int {
	// 双击启动（没有任何参数）时直接进桌面模式：起 Web 界面并打开浏览器。
	if len(args) == 0 {
		return runDesktop(stderr)
	}
	opt, rest, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "参数错误：", err)
		fmt.Fprintln(stderr, "运行 goport -h 查看完整用法。")
		return 2
	}
	if opt.showVersion {
		fmt.Fprintf(stdout, "goport %s\n", version)
		return 0
	}
	if opt.listIf {
		return listInterfaces(stdout)
	}
	if opt.doctor {
		return doctor(stdout, stderr)
	}
	if opt.web != "" {
		return runWeb(opt.web, stderr, opt.open)
	}

	// ---- build the scan scope -------------------------------------------
	targetArgs := append([]string(opt.targets), rest...)
	if len(targetArgs) == 0 {
		usage(stderr)
		return 2
	}
	targeting, err := scan.ParseTargets(targetArgs)
	for _, w := range targeting.WarningsOrNil() {
		fmt.Fprintln(stderr, "警告：", w)
	}
	if err != nil {
		fmt.Fprintln(stderr, "目标解析失败：", err)
		return 2
	}

	portSpec, err := resolvePorts(opt, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "端口解析失败：", err)
		return 2
	}
	ports, err := scan.ParsePortSpec(portSpec)
	if err != nil {
		fmt.Fprintln(stderr, "端口解析失败：", err)
		return 2
	}

	mode, err := scan.ParseMode(opt.mode)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	format, err := scan.ParseFormat(opt.format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	cfg := &scan.Config{
		Scope:             &scan.Scope{Addrs: targeting.Addrs, Ports: ports},
		Mode:              mode,
		Iface:             opt.iface,
		TTL:               uint8(opt.ttl),
		Rate:              opt.rate,
		Timeout:           time.Duration(opt.timeoutMs) * time.Millisecond,
		Retries:           opt.retries,
		Shuffle:           opt.shuffle,
		Batch:             opt.batch,
		ARPTimeout:        time.Duration(opt.arpTimeoutMs) * time.Millisecond,
		Banner:            opt.banner,
		BannerConcurrency: 64,
		BannerTimeout:     time.Duration(opt.bannerMs) * time.Millisecond,
		Concurrency:       opt.concurrency,
		ShowClosed:        opt.showClosed,
		ShowFiltered:      opt.showFiltered,
		Verbose:           opt.verbose,
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 400 * time.Millisecond
	}
	cfg.Warnf = func(format string, a ...any) {
		fmt.Fprintf(stderr, "[!] "+format+"\n", a...)
	}
	if opt.srcIP != "" {
		ip, err := parseAddr(opt.srcIP)
		if err != nil {
			fmt.Fprintf(stderr, "-src-ip %s 无效：%v\n", opt.srcIP, err)
			return 2
		}
		cfg.SrcIP = ip
	}
	if opt.srcMAC != "" {
		mac, err := packetParseMAC(opt.srcMAC)
		if err != nil {
			fmt.Fprintf(stderr, "-src-mac %s 无效：%v\n", opt.srcMAC, err)
			return 2
		}
		cfg.SrcMAC = mac
	}
	if opt.gwMAC != "" {
		mac, err := packetParseMAC(opt.gwMAC)
		if err != nil {
			fmt.Fprintf(stderr, "-gw-mac %s 无效：%v\n", opt.gwMAC, err)
			return 2
		}
		cfg.GwMAC = mac
	}
	if opt.verbose {
		cfg.Logf = func(format string, a ...any) {
			fmt.Fprintf(stderr, "[*] "+format+"\n", a...)
		}
	}

	if opt.dryRun {
		return dryRun(cfg, ports, stdout, stderr)
	}

	// ---- run -------------------------------------------------------------
	outStream := stdout
	var file *os.File
	if opt.out != "" {
		file, err = os.Create(opt.out)
		if err != nil {
			fmt.Fprintln(stderr, "无法创建输出文件：", err)
			return 1
		}
		defer file.Close()
		outStream = file
	}
	color := file == nil && opt.out == "" && supportsColor(stdout) && !opt.noColor && os.Getenv("NO_COLOR") == ""
	sink := scan.NewSink(outStream, format, color)
	// -csv-enc gbk 让 CSV 用 GB2312/GBK 写出，中文 Windows 的 Excel 直接双击即可正确显示。
	if format == scan.FormatCSV && isGBK(opt.csvEnc) {
		if enc.Available() {
			sink.SetCSVEncoder(enc.ToGBK)
		} else {
			fmt.Fprintln(stderr, "警告：当前系统不支持 GBK 转换，CSV 仍以 UTF-8 写出")
		}
	}

	printBannerLine(stderr, cfg, targeting, ports, opt)

	if opt.noProgress || file != nil {
		// A file sink keeps the console free for the progress line.
	} else if format != scan.FormatTable {
		opt.noProgress = true
	}
	if !opt.noProgress && isTerminal(stderr) {
		cfg.Progress = progressPrinter(stderr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	stats, scanErr := scan.Run(ctx, cfg, sink.Emit)
	if err := sink.Close(); err != nil && scanErr == nil {
		scanErr = err
	}
	clearProgress(stderr)

	if file != nil {
		// Echo the findings to the console as well when writing a file.
	}

	elapsed := time.Since(started)
	if cfg.UsedMode != "" && cfg.UsedMode != cfg.Mode {
		fmt.Fprintf(stderr, "[*] 实际扫描模式：%s（请求的是 %s）\n", cfg.UsedMode, cfg.Mode)
	}
	if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		fmt.Fprintln(stderr, "扫描出错：", scanErr)
		summary(stderr, stats, sink.Count(), elapsed, len(targeting.Addrs), ports)
		return 1
	}
	interrupted := ctx.Err() != nil
	summary(stderr, stats, sink.Count(), elapsed, len(targeting.Addrs), ports)
	if file != nil {
		fmt.Fprintf(stderr, "结果已写入 %s（%d 条）\n", opt.out, sink.Count())
	}
	if interrupted {
		fmt.Fprintln(stderr, "扫描被中断，以上为部分结果。")
		return 130
	}
	if scanErr != nil {
		return 1
	}
	return 0
}

// isGBK 判断 -csv-enc 是否要求 GB2312/GBK 代码页。
func isGBK(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "gbk", "gb2312", "gb-2312", "cp936", "936", "ansi":
		return true
	}
	return false
}

// resolvePorts picks the port specification from -ports / -preset / Goby config.
func resolvePorts(opt options, stderr io.Writer) (string, error) {
	if opt.gobyConfig != "" {
		presets, err := scan.LoadGobyPresets(opt.gobyConfig)
		if err != nil {
			return "", err
		}
		name := strings.ToLower(strings.TrimSpace(opt.preset))
		name = strings.ReplaceAll(name, " ", "")
		name = strings.ReplaceAll(name, "/", "-")
		if spec, ok := presets[name]; ok && opt.ports == "" {
			fmt.Fprintf(stderr, "[*] 使用 Goby 预设 %q：%d 个端口条目\n", opt.preset, countTokens(spec))
			return spec, nil
		}
		if opt.preset != "" && opt.ports == "" {
			var names []string
			for k := range presets {
				names = append(names, k)
			}
			sort.Strings(names)
			return "", fmt.Errorf("Goby 配置里没有预设 %q（可用：%s）", opt.preset, strings.Join(names, ", "))
		}
	}
	if opt.ports != "" {
		// "-p minimal" is accepted as a synonym for "-preset minimal".
		if spec, ok := scan.LookupPreset(opt.ports); ok {
			return spec, nil
		}
		return opt.ports, nil
	}
	if opt.preset != "" {
		if spec, ok := scan.LookupPreset(opt.preset); ok {
			return spec, nil
		}
		return "", fmt.Errorf("未知预设 %q（可用：%s）", opt.preset, strings.Join(scan.PresetNames(), ", "))
	}
	spec, _ := scan.LookupPreset("minimal")
	return spec, nil
}

func countTokens(spec string) int {
	n := 0
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			n++
		}
	}
	return n
}

func printBannerLine(stderr io.Writer, cfg *scan.Config, t *scan.Targeting, ports scan.PortSet, opt options) {
	fmt.Fprintf(stderr, "%s goport %s  |  模式 %s  目标 %d 个  端口 %d 个（TCP %d / UDP %d）\n",
		bold(stderr), version, cfg.Mode, len(t.Addrs), ports.Total(), len(ports.TCP), len(ports.UDP))
	if cfg.Mode == scan.ModeSYN {
		fmt.Fprintf(stderr, "[*] 速率 %d pps，超时 %s，重传 %d 次\n", opt.rate, cfg.Timeout, opt.retries)
	} else {
		fmt.Fprintf(stderr, "[*] 并发 %d，超时 %s\n", opt.concurrency, cfg.Timeout)
	}
}

func summary(w io.Writer, st scan.Stats, found int, elapsed time.Duration, hosts int, ports scan.PortSet) {
	fmt.Fprintf(w, "\n扫描完成，用时 %s\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "  目标 %d 个（无响应 %d），端口 %d 个，共 %d 个探测\n",
		hosts, st.HostsDead, ports.Total(), st.Probes)
	if st.Sent > 0 {
		fmt.Fprintf(w, "  发送 %d 个探测（重传 %d，平均 %.0f pps），收到 %d 个应答\n",
			st.Sent, st.Retransmits, st.PPS, st.Received)
	}
	fmt.Fprintf(w, "  结果：open %d，closed %d，filtered %d，已输出 %d 行\n",
		st.Open, st.Closed, st.Filtered, found)
}

// ---- environment helpers ----------------------------------------------

func listInterfaces(w io.Writer) int {
	fmt.Fprintf(w, "Npcap：%s\n\n", npcap.Version())
	ads, err := netinfo.Adapters()
	if err != nil {
		fmt.Fprintln(w, "枚举网卡失败：", err)
		return 1
	}
	defIdx, gw, hasDef := netinfo.DefaultRoute()
	fmt.Fprintln(w, "可用网卡：")
	for _, a := range ads {
		mark := "  "
		if hasDef && a.Index == defIdx {
			mark = "* "
		}
		fmt.Fprintf(w, "%s%s\n", mark, a.String())
		fmt.Fprintf(w, "     npcap 设备：%s\n", a.Device)
		if p, ok := a.Prefix(); ok {
			fmt.Fprintf(w, "     网段：%s\n", p)
		}
	}
	if hasDef {
		fmt.Fprintf(w, "\n默认路由网卡 #%d，网关 %s（* 标记）\n", defIdx, gw)
	}
	fmt.Fprintln(w, "\n用 -i <编号|名称> 指定网卡，例如 -i 6 或 -i WLAN")
	return 0
}

// supportsColor reports whether the console can render ANSI escapes.
func supportsColor(w io.Writer) bool { return isTerminal(w) }

// isTerminal reports whether w is a character device (a real console).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func bold(w io.Writer) string {
	if isTerminal(w) {
		return "\x1b[1m"
	}
	return ""
}

func progressPrinter(w io.Writer) func(scan.Stats) {
	return func(s scan.Stats) {
		fmt.Fprintf(w, "\r%5.1f%%  %-64s", s.Progress(), s.String())
	}
}

func clearProgress(w io.Writer) {
	if isTerminal(w) {
		fmt.Fprint(w, "\r"+strings.Repeat(" ", 90)+"\r")
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `goport %s —— 基于 Npcap 的高速端口扫描器

用法:
  goport -t <目标> [选项]

目标 (-t，可重复；也可直接作为位置参数):
  10.0.0.1                单个地址
  10.0.0.0/24             网段
  10.0.0.1-254            最后一段范围
  10.0.0.1-10.0.0.9       任意范围
  example.com             域名
  hosts.txt               目标文件（每行一个，# 为注释）

端口:
  -p, -ports <列表>       例如 "80,443,8000-8100,U:161"、"all"
  -preset <名称>          Goby 预设: %s
  -goby-config <路径>     直接读取 Goby 的 config/config.json 预设

扫描控制:
  -m, -mode <auto|syn|connect>
                          默认 auto：优先 SYN，无管理员权限时自动退回 connect
  -i, -iface <编号|名称>   指定网卡，先用 -list-if 查看
  -rate <pps>             每秒探测数（默认 2000）
  -timeout <毫秒>         单次探测超时（默认 400）
  -retries <次数>         无响应重传次数（默认 2）
  -shuffle                随机化探测顺序
  -batch / -no-batch      批量发送（更快，部分驱动会丢应答，默认关闭）
  -ttl <ttl>              探测报文 TTL（默认 64）
  -arp-timeout <毫秒>     同网段 ARP 解析窗口（默认 3000）
  -c, -concurrency <n>    connect 模式并发（默认 500）

结果:
  -banner                 识别服务版本（默认开启）
  -no-banner              关闭服务识别
  -show-closed            输出 closed 端口
  -show-filtered          输出 filtered 端口
  -f, -format <格式>      table | json | ndjson | csv（默认 table）
  -csv-enc <编码>         CSV 编码：utf8（默认）/ gbk（GB2312，Excel 友好）
  -o, -out <文件>         结果写入文件
  -no-color               关闭颜色

其他:
  -list-if                列出网卡与 Npcap 设备名
  -doctor                 环境自检（Npcap / 权限 / 路由）
  -web <地址>              启动 Web 界面，如 -web 127.0.0.1:8080
  -ui                      同上，等价于 -web 127.0.0.1:8080
  -dry-run                只构造报文并校验校验和，不发送
  -v, -verbose            详细日志
  -V, -version            打印版本

示例:
  goport -t 192.168.1.0/24 -p minimal
  goport -t 10.0.0.5 -p all -rate 20000 -o open.txt
  goport -t 10.0.0.0/24 -preset enterprise -m connect
  goport -t 10.0.0.5 -p 1-65535 -f json | jq .
  goport -web 127.0.0.1:8080        # 浏览器里填 IP / 端口点按钮扫描
`, version, strings.Join(scan.PresetNames(), ", "))
}
