package scan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"goport/internal/netinfo"
	"goport/internal/npcap"
	"goport/internal/packet"
)

// Mode selects the scan technique.
type Mode string

const (
	// ModeSYN injects raw SYN frames through Npcap (stateless, fastest, and
	// invisible to the target's accept queue). Requires administrator rights.
	ModeSYN Mode = "syn"
	// ModeConnect uses ordinary TCP connect() calls. Slower, but needs no
	// driver access and works through any local proxy/firewall policy.
	ModeConnect Mode = "connect"
	// ModeAuto prefers SYN and transparently falls back to connect when the
	// Npcap driver cannot be opened (typically: not running elevated).
	ModeAuto Mode = "auto"
)

// ParseMode accepts the CLI spellings of the scan modes.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "a", "":
		return ModeAuto, nil
	case "syn", "s", "half", "half-open":
		return ModeSYN, nil
	case "connect", "c", "full", "tcp":
		return ModeConnect, nil
	}
	return "", fmt.Errorf("未知扫描模式 %q（支持 auto / syn / connect）", s)
}

// Config drives a scan. The exported fields come from the command line; the
// unexported ones are filled in by prepare().
type Config struct {
	Scope *Scope
	Mode  Mode

	// interface selection
	Iface string // adapter index/name substring, empty = default route

	// engine tuning
	TTL     uint8
	Rate    int // probes per second
	Timeout time.Duration
	Retries int
	Shuffle bool
	Batch   bool // use pcap_sendqueue batching when available

	// host discovery
	ARPTimeout time.Duration
	SrcIP      netip.Addr
	SrcMAC     packet.MAC
	GwMAC      packet.MAC

	// detection
	Banner            bool
	BannerConcurrency int
	BannerTimeout     time.Duration
	Concurrency       int // connect mode workers

	// reporting
	ShowClosed   bool
	ShowFiltered bool
	Verbose      bool
	// UsedMode records the mode actually used for the scan (auto may fall back).
	UsedMode Mode

	Progress func(Stats)
	Logf     func(string, ...any)
	// Warnf reports a non-fatal condition the user must know about, so it is
	// shown even without -verbose (e.g. the auto fallback to connect mode).
	Warnf func(string, ...any)

	// filled by prepare()
	link        packet.Link
	srcIP       packet.IPv4
	srcMAC      packet.MAC
	adapter     netinfo.Adapter
	sendH       *npcap.Handle
	recvH       *npcap.Handle
	macs        map[uint32]packet.MAC
	activeHosts []uint32
	emit        func(Result)
	startedAt   time.Time
	hostsDead   int
}

// logf logs only when a logger is configured.
func (c *Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// warnf reports a non-fatal condition to the user.
func (c *Config) warnf(format string, args ...any) {
	if c.Warnf != nil {
		c.Warnf(format, args...)
	}
}

func (c *Config) validate() error {
	if c.Scope == nil || len(c.Scope.Addrs) == 0 {
		return errors.New("没有目标地址")
	}
	if c.Scope.Ports.Total() == 0 {
		return errors.New("没有目标端口")
	}
	if c.Mode == "" {
		c.Mode = ModeSYN
	}
	if c.Rate <= 0 {
		c.Rate = 2000
	}
	if c.Timeout <= 0 {
		c.Timeout = 400 * time.Millisecond
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	if c.ARPTimeout <= 0 {
		c.ARPTimeout = 3 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 500
	}
	if c.BannerConcurrency <= 0 {
		c.BannerConcurrency = 64
	}
	if c.BannerTimeout <= 0 {
		c.BannerTimeout = 1200 * time.Millisecond
	}
	return nil
}

// Run performs the scan, calling out for every result the user should see. out
// may be called from several goroutines, so the sink must be safe for
// concurrent use.
func Run(ctx context.Context, cfg *Config, out func(Result)) (Stats, error) {
	if err := cfg.validate(); err != nil {
		return Stats{}, err
	}
	cfg.startedAt = time.Now()

	// Banner detection runs in a worker pool fed by open results, so results
	// stream out with version info attached instead of being buffered.
	var (
		bannerCh chan Result
		workers  sync.WaitGroup
	)
	if cfg.Banner {
		bannerCh = make(chan Result, 8192)
		for i := 0; i < cfg.BannerConcurrency; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for r := range bannerCh {
					enrichBanner(&r, cfg.BannerTimeout)
					out(r)
				}
			}()
		}
	}
	cfg.emit = func(r Result) {
		if bannerCh != nil && r.State == StateOpen.String() && r.Proto == "tcp" {
			select {
			case bannerCh <- r:
				return
			default:
				// queue full: report immediately rather than stalling capture
			}
		}
		out(r)
	}

	var (
		stats Stats
		err   error
	)
	switch cfg.Mode {
	case ModeConnect:
		cfg.UsedMode = ModeConnect
		stats, err = runConnect(ctx, cfg)
	case ModeSYN:
		cfg.UsedMode = ModeSYN
		stats, err = runSYN(ctx, cfg)
	default: // ModeAuto
		stats, err = runSYN(ctx, cfg)
		if err != nil {
			// The usual cause is a non-elevated process: Npcap refuses to open
			// the driver. A connect() scan gets the same port states without it.
			if ctx.Err() != nil {
				break
			}
			cfg.warnf("SYN 模式不可用（%v）\n继续改用 connect 模式扫描（结果相同，速率与隐蔽性略差）。", err)
			cfg.warnf("若希望使用 SYN 模式，请用「以管理员身份运行」的终端重新执行。")
			cfg.UsedMode = ModeConnect
			stats, err = runConnect(ctx, cfg)
		} else {
			cfg.UsedMode = ModeSYN
		}
	}

	if bannerCh != nil {
		close(bannerCh)
		workers.Wait()
	}
	return stats, err
}

// runSYN prepares the raw environment and drives the SYN scanner.
func runSYN(ctx context.Context, cfg *Config) (Stats, error) {
	cleanup, err := cfg.prepare(ctx)
	if err != nil {
		return Stats{}, err
	}
	defer cleanup()

	sc := newSYNScanner(cfg, cfg.activeHosts, cfg.macs)
	sc.send = cfg.sendH
	sc.recv = cfg.recvH
	if cfg.Batch {
		if bq := npcap.NewBatchQueue(cfg.sendH, 1<<20); bq.Usable {
			sc.batch = bq
			defer bq.Free()
		} else if cfg.Verbose {
			cfg.logf("批量发送不可用，退回单包发送")
		}
	}
	sc.run(ctx)
	return sc.stats(), nil
}

// EnvInfo is the raw-scan environment resolved without touching the driver.
type EnvInfo struct {
	Adapter netinfo.Adapter
	SrcIP   packet.IPv4
	SrcMAC  packet.MAC
	Target  netip.Addr
	OnLink  bool
	Gateway netip.Addr
	HasGW   bool
}

// ResolveEnv works out which adapter, source address and source MAC a scan
// would use. It needs no driver access, so -dry-run and -doctor can use it.
func ResolveEnv(cfg *Config) (EnvInfo, error) {
	var info EnvInfo
	if cfg.Scope == nil || len(cfg.Scope.Addrs) == 0 {
		return info, errors.New("没有目标地址")
	}
	ads, err := netinfo.Adapters()
	if err != nil {
		return info, err
	}
	ad, err := pickAdapter(ads, cfg.Iface, cfg.Scope.Addrs[0])
	if err != nil {
		return info, err
	}
	info.Adapter = ad
	info.Target = netinfo.U32ToAddr(cfg.Scope.Addrs[0])

	if cfg.SrcIP.IsValid() {
		ip, ok := packet.IPv4From(cfg.SrcIP)
		if !ok {
			return info, fmt.Errorf("源地址 %s 不是 IPv4", cfg.SrcIP)
		}
		info.SrcIP = ip
	} else {
		ip, err := chooseSourceIP(ad, cfg.Scope.Addrs[0])
		if err != nil {
			return info, err
		}
		info.SrcIP = ip
	}

	if !cfg.SrcMAC.IsZero() {
		info.SrcMAC = cfg.SrcMAC
	} else if mac, ok := ad.MAC6(); ok && usableMAC(mac) {
		info.SrcMAC = mac
	} else if !ad.Loopback {
		return info, fmt.Errorf("无法读取网卡 %s 的 MAC 地址，请用 -src-mac 指定（如 -src-mac aa:bb:cc:dd:ee:ff）", ad.Label())
	}

	if prefix, ok := ad.Prefix(); ok {
		info.OnLink = prefix.Contains(info.Target)
	} else {
		info.OnLink = true
	}
	if idx, gw, ok := netinfo.DefaultRoute(); ok {
		info.Gateway = gw
		info.HasGW = true
		_ = idx
	}
	return info, nil
}

// prepare wires up the capture device, resolves next-hop MACs, and leaves the
// scan-ready state on cfg.
func (c *Config) prepare(ctx context.Context) (func(), error) {
	// Fail fast when the driver is guaranteed to refuse us: Npcap takes seconds
	// to report the access error, and auto mode should fall back instantly.
	if !npcap.CanInject() {
		return nil, errors.New("Npcap 驱动只允许管理员访问（AdminOnly=1），当前进程未以管理员身份运行")
	}
	env, err := ResolveEnv(c)
	if err != nil {
		return nil, err
	}
	ad := env.Adapter
	c.adapter = ad
	c.srcIP = env.SrcIP
	c.srcMAC = env.SrcMAC

	if c.Verbose {
		c.logf("网卡：%s（%s）  源 IP：%s  源 MAC：%s", ad.Label(), ad.Device, c.srcIP, c.srcMAC)
	}

	sendH, err := npcap.OpenLive(ad.Device, 65536, 20, false)
	if err != nil {
		return nil, fmt.Errorf("%w\n  网卡：%s (%s)", err, ad.Label(), ad.Device)
	}
	recvH, err := npcap.OpenLive(ad.Device, 65536, 50, true)
	if err != nil {
		sendH.Close()
		return nil, fmt.Errorf("%w\n  网卡：%s (%s)", err, ad.Label(), ad.Device)
	}
	cleanup := func() {
		sendH.Close()
		recvH.Close()
	}

	switch dl := sendH.DataLink(); dl {
	case npcap.DLTEn10MB:
		c.link = packet.LinkEthernet
	case npcap.DLTNull:
		c.link = packet.LinkNull
	default:
		cleanup()
		return nil, fmt.Errorf("不支持的链路层类型 %d（仅支持以太网与 Npcap Loopback）", dl)
	}
	// A 4 MiB capture buffer absorbs the reply burst that a fast scan provokes;
	// without it the driver drops SYN-ACK/RST frames and open ports look filtered.
	if err := recvH.SetBuffer(4 << 20); err != nil && c.Verbose {
		c.logf("扩大抓包缓冲区失败（继续使用默认值）：%v", err)
	}
	if err := recvH.SetFilter("ip"); err != nil {
		cleanup()
		return nil, err
	}

	c.sendH = sendH
	c.recvH = recvH

	// Resolve next-hop MACs for every target.
	macs, dead, err := c.resolveMACs(ctx)
	if err != nil {
		cleanup()
		return nil, err
	}
	c.hostsDead = dead
	c.macs = macs
	c.activeHosts = c.activeHosts[:0]
	for _, h := range c.Scope.Addrs {
		if _, ok := macs[h]; ok {
			c.activeHosts = append(c.activeHosts, h)
		}
	}
	if len(c.activeHosts) == 0 {
		cleanup()
		return nil, fmt.Errorf("%d 个目标都没有响应 ARP（不在线或被防火墙拦截）", len(c.Scope.Addrs))
	}
	if c.Verbose {
		c.logf("存活目标 %d/%d", len(c.activeHosts), len(c.Scope.Addrs))
	}
	return cleanup, nil
}

// resolveMACs maps every host onto the MAC its frames must be sent to.
func (c *Config) resolveMACs(ctx context.Context) (map[uint32]packet.MAC, int, error) {
	macs := make(map[uint32]packet.MAC, len(c.Scope.Addrs))
	if c.link == packet.LinkNull {
		// Loopback has no MAC layer; frames go out with a zero address.
		for _, h := range c.Scope.Addrs {
			macs[h] = packet.MAC{}
		}
		return macs, 0, nil
	}

	seed := arpSeed()
	prefix, hasPrefix := c.adapter.Prefix()
	onLink := func(h uint32) bool {
		if !hasPrefix {
			return true
		}
		return prefix.Contains(netinfo.U32ToAddr(h))
	}

	var onLinkHosts, offLinkHosts []uint32
	for _, h := range c.Scope.Addrs {
		if onLink(h) {
			onLinkHosts = append(onLinkHosts, h)
		} else {
			offLinkHosts = append(offLinkHosts, h)
		}
	}

	if len(onLinkHosts) > 0 {
		resolved, err := arpResolve(ctx, c.adapter.Device, c.srcIP, c.srcMAC, onLinkHosts, c.ARPTimeout, c.Rate, seed)
		if err != nil {
			return nil, 0, fmt.Errorf("ARP 探测失败：%w", err)
		}
		for h, m := range resolved {
			if usableMAC(m) {
				macs[h] = m
			}
		}
	}

	if len(offLinkHosts) > 0 {
		gwMAC := c.GwMAC
		if !usableMAC(gwMAC) {
			if gwIdx, gw, ok := netinfo.DefaultRoute(); ok {
				_ = gwIdx
				if cached, found := seed[netinfo.AddrToU32(gw)]; found && usableMAC(cached) {
					gwMAC = cached
				} else {
					resolved, err := arpResolve(ctx, c.adapter.Device, c.srcIP, c.srcMAC,
						[]uint32{netinfo.AddrToU32(gw)}, c.ARPTimeout, 100, nil)
					if err != nil {
						return nil, 0, fmt.Errorf("解析网关 %s 的 MAC 失败：%w", gw, err)
					}
					if m, ok := resolved[netinfo.AddrToU32(gw)]; ok && usableMAC(m) {
						gwMAC = m
					}
				}
			}
		}
		if !usableMAC(gwMAC) {
			return nil, 0, errors.New("跨网段扫描需要网关 MAC，但解析失败；请用 -gw-mac 指定")
		}
		if c.Verbose {
			c.logf("跨网段目标 %d 个，下一跳网关 MAC：%s", len(offLinkHosts), gwMAC)
		}
		for _, h := range offLinkHosts {
			macs[h] = gwMAC
		}
	}
	return macs, len(c.Scope.Addrs) - len(macs), nil
}

// arpSeed turns the Windows ARP cache into the scanner's MAC map.
func arpSeed() map[uint32]packet.MAC {
	cache := netinfo.ARPCache()
	seed := make(map[uint32]packet.MAC, len(cache))
	for ip, raw := range cache {
		var mac packet.MAC
		copy(mac[:], raw[:])
		if usableMAC(mac) {
			seed[netinfo.AddrToU32(ip)] = mac
		}
	}
	return seed
}

// pickAdapter chooses the capture interface.
func pickAdapter(ads []netinfo.Adapter, sel string, firstTarget uint32) (netinfo.Adapter, error) {
	if sel != "" {
		return netinfo.MatchAdapter(ads, sel)
	}
	// All-loopback scans use the Npcap loopback device.
	if netinfo.IsLoopbackTarget(netinfo.U32ToAddr(firstTarget)) {
		return netinfo.LoopbackAdapter(), nil
	}
	if idx, _, ok := netinfo.DefaultRoute(); ok {
		for _, a := range ads {
			if a.Index == idx && len(a.IPv4) > 0 {
				return a, nil
			}
		}
	}
	// Fall back to an interface that covers the target, then any live one.
	target := netinfo.U32ToAddr(firstTarget)
	for _, a := range ads {
		if p, ok := a.Prefix(); ok && a.Up && p.Contains(target) {
			return a, nil
		}
	}
	for _, a := range ads {
		if a.Up && len(a.IPv4) > 0 && !strings.Contains(strings.ToLower(a.Desc), "loopback") {
			return a, nil
		}
	}
	return netinfo.Adapter{}, errors.New("找不到可用的网卡，请用 -list-if 查看并用 -i 指定")
}

// chooseSourceIP picks the adapter address that best covers the target.
func chooseSourceIP(ad netinfo.Adapter, target uint32) (packet.IPv4, error) {
	if len(ad.IPv4) == 0 {
		return packet.IPv4{}, fmt.Errorf("网卡 %s 没有 IPv4 地址", ad.Label())
	}
	t := netinfo.U32ToAddr(target)
	for i, ip := range ad.IPv4 {
		if i < len(ad.Masks) {
			bits := netinfo.MaskBits(ad.Masks[i])
			if bits >= 0 && netip.PrefixFrom(ip, bits).Contains(t) {
				return packet.IPv4(ip.As4()), nil
			}
		}
	}
	return packet.IPv4(ad.IPv4[0].As4()), nil
}
