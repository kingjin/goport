package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"goport/internal/netinfo"
	"goport/internal/npcap"
	"goport/internal/packet"
	"goport/internal/scan"
)

// parseFlags defines the command line. Aliases simply share one variable.
func parseFlags(args []string, stderr io.Writer) (options, []string, error) {
	var opt options
	fs := flag.NewFlagSet("goport", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print our own usage text
	fs.Usage = func() {}

	// targets
	fs.Var(&opt.targets, "t", "目标")
	fs.Var(&opt.targets, "target", "目标")

	// ports
	fs.StringVar(&opt.ports, "p", "", "端口列表")
	fs.StringVar(&opt.ports, "ports", "", "端口列表")
	fs.StringVar(&opt.preset, "preset", "", "Goby 端口预设")
	fs.StringVar(&opt.preset, "presets", "", "Goby 端口预设")
	fs.StringVar(&opt.gobyConfig, "goby-config", "", "Goby config.json 路径")

	// engine
	fs.StringVar(&opt.iface, "i", "", "网卡")
	fs.StringVar(&opt.iface, "iface", "", "网卡")
	fs.StringVar(&opt.iface, "interface", "", "网卡")
	fs.StringVar(&opt.mode, "m", "auto", "扫描模式")
	fs.StringVar(&opt.mode, "mode", "auto", "扫描模式")
	fs.IntVar(&opt.rate, "rate", 2000, "每秒探测数")
	fs.IntVar(&opt.timeoutMs, "timeout", 400, "超时毫秒")
	fs.IntVar(&opt.retries, "retries", 2, "重传次数")
	fs.BoolVar(&opt.shuffle, "shuffle", false, "随机化顺序")
	fs.BoolVar(&opt.batch, "batch", false, "批量发送（更快，部分驱动会丢应答）")
	var noBatch bool
	fs.BoolVar(&noBatch, "no-batch", false, "关闭批量发送")
	fs.IntVar(&opt.ttl, "ttl", 64, "TTL")
	fs.IntVar(&opt.arpTimeoutMs, "arp-timeout", 3000, "ARP 窗口毫秒")
	fs.IntVar(&opt.concurrency, "c", 500, "connect 并发")
	fs.IntVar(&opt.concurrency, "concurrency", 500, "connect 并发")

	// source overrides
	fs.StringVar(&opt.srcIP, "src-ip", "", "源 IP")
	fs.StringVar(&opt.srcMAC, "src-mac", "", "源 MAC")
	fs.StringVar(&opt.gwMAC, "gw-mac", "", "网关 MAC")

	// detection
	fs.BoolVar(&opt.banner, "banner", true, "服务识别")
	var noBanner bool
	fs.BoolVar(&noBanner, "no-banner", false, "关闭服务识别")
	fs.IntVar(&opt.bannerMs, "banner-timeout", 1200, "服务识别超时毫秒")

	// reporting
	fs.BoolVar(&opt.showClosed, "show-closed", false, "输出 closed")
	fs.BoolVar(&opt.showFiltered, "show-filtered", false, "输出 filtered")
	fs.StringVar(&opt.format, "f", "table", "输出格式")
	fs.StringVar(&opt.format, "format", "table", "输出格式")
	fs.StringVar(&opt.out, "o", "", "结果文件")
	fs.StringVar(&opt.out, "out", "", "结果文件")
	fs.StringVar(&opt.csvEnc, "csv-enc", "utf8", "CSV 编码（utf8 / gbk）")
	fs.BoolVar(&opt.noColor, "no-color", false, "关闭颜色")
	fs.BoolVar(&opt.noProgress, "no-progress", false, "关闭进度行")

	// misc
	fs.BoolVar(&opt.verbose, "v", false, "详细日志")
	fs.BoolVar(&opt.verbose, "verbose", false, "详细日志")
	fs.BoolVar(&opt.listIf, "list-if", false, "列出网卡")
	fs.BoolVar(&opt.doctor, "doctor", false, "环境自检")
	fs.StringVar(&opt.web, "web", "", "启动 Web 界面")
	fs.BoolVar(&opt.ui, "ui", false, "启动 Web 界面（127.0.0.1:8080）")
	fs.BoolVar(&opt.open, "open", false, "启动 Web 界面后自动打开浏览器")
	fs.BoolVar(&opt.dryRun, "dry-run", false, "只构造报文")
	fs.BoolVar(&opt.showVersion, "V", false, "版本")
	fs.BoolVar(&opt.showVersion, "version", false, "版本")

	if err := fs.Parse(args); err != nil {
		return opt, nil, err
	}
	if opt.ui && opt.web == "" {
		opt.web = "127.0.0.1:8080"
	}
	if noBatch {
		opt.batch = false
	}
	if noBanner {
		opt.banner = false
	}
	return opt, fs.Args(), nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

func packetParseMAC(s string) (packet.MAC, error) { return packet.ParseMAC(s) }

// doctor checks the runtime prerequisites and prints a verdict.
func doctor(stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "GoPort %s 环境自检\n", version)
	problems := 0
	ok := func(format string, a ...any) {
		fmt.Fprintf(stdout, "  [ OK ] "+format+"\n", a...)
	}
	warn := func(format string, a ...any) {
		fmt.Fprintf(stdout, "  [WARN] "+format+"\n", a...)
	}
	bad := func(format string, a ...any) {
		problems++
		fmt.Fprintf(stdout, "  [FAIL] "+format+"\n", a...)
	}

	// 1. Npcap driver / DLL
	if err := npcap.Load(); err != nil {
		bad("%v", err)
		fmt.Fprintln(stdout, "\n请先安装 Npcap（https://npcap.com/#download），安装时勾选 winpcap 兼容模式。")
		return 1
	}
	ok("wpcap.dll 已加载：%s", npcap.Version())

	// 2. adapters
	ads, err := netinfo.Adapters()
	if err != nil {
		bad("枚举网卡失败：%v", err)
		return 1
	}
	up := 0
	for _, a := range ads {
		if a.Up && len(a.IPv4) > 0 {
			up++
		}
	}
	if up == 0 {
		bad("没有处于启用状态且带 IPv4 地址的网卡")
	} else {
		ok("发现 %d 块网卡，其中 %d 块可用", len(ads), up)
	}

	// 3. default route
	if idx, gw, has := netinfo.DefaultRoute(); has {
		ok("默认路由：网卡 #%d，网关 %s", idx, gw)
	} else {
		warn("没有默认路由，跨网段扫描需要 -i 指定网卡并用 -gw-mac 指定网关 MAC")
	}

	// 4. ARP cache (used to skip ARP probing)
	if cache := netinfo.ARPCache(); len(cache) > 0 {
		ok("系统 ARP 表缓存了 %d 个条目", len(cache))
	} else {
		warn("系统 ARP 表为空")
	}

	// 5. driver access = the real privilege test
	if npcap.IsElevated() {
		ok("当前进程以管理员权限运行")
	} else {
		warn("当前进程不是管理员权限，SYN 模式无法打开 Npcap 驱动（可用 -m connect 或提权后运行）")
	}
	target := ""
	if idx, _, has := netinfo.DefaultRoute(); has {
		for _, a := range ads {
			if a.Index == idx {
				target = a.Device
			}
		}
	}
	if target == "" {
		for _, a := range ads {
			if a.Up && len(a.IPv4) > 0 {
				target = a.Device
				break
			}
		}
	}
	if target == "" {
		bad("找不到可测试的网卡设备名")
	} else {
		h, err := npcap.OpenLive(target, 65536, 20, false)
		if err != nil {
			bad("打开网卡失败：%v", err)
			fmt.Fprintln(stdout, "\nNpcap 驱动默认只允许管理员访问。请右键「以管理员身份运行」终端后重试，")
			fmt.Fprintln(stdout, "或改用 -m connect（无需驱动）。")
		} else {
			dl := h.DataLink()
			h.Close()
			name := map[int]string{npcap.DLTEn10MB: "Ethernet", npcap.DLTNull: "Null/Loopback"}[dl]
			if name == "" {
				name = fmt.Sprintf("未知(%d)", dl)
			}
			ok("抓包权限正常，链路层 %s", name)
		}
	}

	// 6. statistics of the port presets, so users see what the presets mean
	minimal, _ := scan.LookupPreset("minimal")
	if ports, err := scan.ParsePortSpec(minimal); err == nil {
		ok("预设 minimal 解析正确：TCP %d 个 / UDP %d 个", len(ports.TCP), len(ports.UDP))
	} else {
		bad("预设解析失败：%v", err)
	}

	fmt.Fprintln(stdout)
	if problems == 0 {
		fmt.Fprintln(stdout, "自检通过，可以直接开始扫描。")
		return 0
	}
	fmt.Fprintf(stdout, "自检发现 %d 个问题，请按上面的提示处理。\n", problems)
	return 1
}

// dryRun crafts example frames, verifies the checksums and dumps them. It needs
// no driver access, which makes it the way to validate the packet layer on a
// machine where the scan itself cannot run elevated.
func dryRun(cfg *scan.Config, ports scan.PortSet, stdout, stderr io.Writer) int {
	env, err := scan.ResolveEnv(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "环境解析失败：", err)
		return 1
	}
	dstMAC := env.SrcMAC
	if info, err := scan.ResolveEnv(cfg); err == nil {
		_ = info
	}
	fmt.Fprintln(stdout, "GoPort dry-run：只构造报文，不发送，也不需要 Npcap 权限")
	fmt.Fprintf(stdout, "  网卡      : %s (%s)\n", env.Adapter.Label(), env.Adapter.Device)
	fmt.Fprintf(stdout, "  源 IP/MAC : %s / %s\n", env.SrcIP, env.SrcMAC)
	fmt.Fprintf(stdout, "  目标      : %s（%s）\n", env.Target, onLinkText(env.OnLink))
	if env.HasGW {
		fmt.Fprintf(stdout, "  网关      : %s\n", env.Gateway)
	}
	// The next hop MAC is only known at scan time (ARP); use a placeholder here
	// so the dump stays deterministic.
	dstMAC = packet.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	b := packet.NewBuilder(packet.LinkEthernet)
	b.TTL = cfg.TTL
	tcpPort := uint16(443)
	if len(ports.TCP) > 0 {
		tcpPort = ports.TCP[0]
	}
	udpPort := uint16(53)
	if len(ports.UDP) > 0 {
		udpPort = ports.UDP[0]
	}
	dst := packet.IPv4(env.Target.As4())

	buf := make([]byte, 128)
	n := b.BuildTCPSYN(buf, dstMAC, env.SrcMAC, env.SrcIP, dst, 40001, tcpPort, 0x12345678)
	frame := buf[:n]
	fmt.Fprintf(stdout, "\nTCP SYN  %s:%d -> %s:%d  (%d 字节)\n", env.SrcIP, 40001, env.Target, tcpPort, n)
	hexdump(stdout, frame)
	fmt.Fprintf(stdout, "  IPv4 校验和: %s\n", checkMark(packet.VerifyIPChecksum(frame[14:34])))
	fmt.Fprintf(stdout, "  TCP  校验和: %s\n", checkMark(packet.VerifyTransportChecksum(frame[14:])))

	if tv, ok := packet.ParseTCP(frame, packet.LinkEthernet); ok {
		fmt.Fprintf(stdout, "  回读: %s:%d -> %d  flags=%#02x seq=%#08x\n", tv.SrcIP, tv.SrcPort, tv.DstPort, tv.Flags, tv.Seq)
	} else {
		fmt.Fprintln(stdout, "  回读失败")
	}

	payload := []byte{}
	n2 := b.BuildUDP(buf, dstMAC, env.SrcMAC, env.SrcIP, dst, 40002, udpPort, payload)
	frame2 := buf[:n2]
	fmt.Fprintf(stdout, "\nUDP      %s:%d -> %s:%d  (%d 字节)\n", env.SrcIP, 40002, env.Target, udpPort, n2)
	hexdump(stdout, frame2)
	fmt.Fprintf(stdout, "  IPv4 校验和: %s\n", checkMark(packet.VerifyIPChecksum(frame2[14:34])))
	fmt.Fprintf(stdout, "  UDP  校验和: %s\n", checkMark(packet.VerifyTransportChecksum(frame2[14:])))

	arp := make([]byte, 42)
	n3 := packet.BuildARPRequest(arp, env.SrcMAC, env.SrcIP, dst)
	fmt.Fprintf(stdout, "\nARP      who-has %s tell %s  (%d 字节)\n", dst, env.SrcIP, n3)
	hexdump(stdout, arp[:n3])
	if v, ok := packet.ParseARP(arp[:n3], packet.LinkEthernet); ok {
		fmt.Fprintf(stdout, "  回读: op=%d %s(%s) -> %s\n", v.Op, v.TargetIP, "who-has", v.SenderIP)
	}

	if !packet.VerifyTransportChecksum(frame[14:]) {
		fmt.Fprintln(stderr, "TCP 校验和验证失败")
		return 1
	}
	fmt.Fprintln(stdout, "\n报文构造正常，可以直接扫描。")
	return 0
}

func onLinkText(onLink bool) string {
	if onLink {
		return "同网段，直接 ARP"
	}
	return "跨网段，走网关"
}

func checkMark(ok bool) string {
	if ok {
		return "正确"
	}
	return "错误"
}

// hexdump prints offset, hex bytes and printable characters.
func hexdump(w io.Writer, b []byte) {
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		row := b[off:end]
		var hex strings.Builder
		var text strings.Builder
		for i := 0; i < 16; i++ {
			if i < len(row) {
				fmt.Fprintf(&hex, "%02x ", row[i])
				if row[i] >= 0x20 && row[i] < 0x7f {
					text.WriteByte(row[i])
				} else {
					text.WriteByte('.')
				}
			} else {
				hex.WriteString("   ")
			}
		}
		fmt.Fprintf(w, "  %04x  %s |%s|\n", off, hex.String(), text.String())
	}
}
