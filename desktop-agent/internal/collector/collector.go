package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	stdnet "net"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v3/host"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type Snapshot struct{}

func NewSnapshotCollector() Snapshot {
	return Snapshot{}
}

func (Snapshot) Name() string {
	return "snapshot.basic"
}

func (Snapshot) Collect(_ context.Context, cfg config.Config) (*types.HostTelemetry, error) {
	now := time.Now().UTC()

	hostInfo, _ := host.Info()
	machineID := resolveMachineID(hostInfo)
	hostname := cfg.HostnameOverride
	if hostname == "" {
		if hn, err := os.Hostname(); err == nil {
			hostname = hn
		}
	}

	telemetry := &types.HostTelemetry{
		Organization:  cfg.Organization,
		Site:          cfg.Site,
		HostID:        machineID,
		Hostname:      hostname,
		SerialNumber:  hostInfo.HostID,
		AgentVersion:  cfg.AgentVersion,
		OSFamily:      detectOSFamily(hostInfo),
		OSVersion:     safeString(hostInfo.PlatformVersion),
		KernelVersion: safeString(hostInfo.KernelVersion),
		Architecture:  runtime.GOARCH,
		CollectedAt:   now,
		IPAddresses:   collectIPAddresses(),
		MacAddresses:  collectMACAddresses(),
		LoggedInUsers: collectUsers(),
		Tags:          cfg.Tags,
		Health: &types.AgentHealth{
			Status:        "healthy",
			LastHeartbeat: now,
		},
	}

	processes, err := collectProcesses(cfg.MaxProcesses)
	if err == nil {
		telemetry.Processes = processes
	}

	if conns, err := collectConnections(); err == nil {
		telemetry.NetworkConnections = conns
	}

	return telemetry, nil
}

func resolveMachineID(info *host.InfoStat) string {
	if info != nil && info.HostID != "" {
		return info.HostID
	}
	if id, err := machineid.ID(); err == nil && id != "" {
		return id
	}
	return uuid.NewString()
}

func detectOSFamily(info *host.InfoStat) string {
	if info == nil {
		return runtime.GOOS
	}
	if info.Platform == "" {
		return runtime.GOOS
	}
	return info.Platform
}

func collectUsers() []string {
	users, err := host.Users()
	if err != nil {
		return nil
	}
	unique := make(map[string]struct{})
	for _, user := range users {
		if user.User == "" {
			continue
		}
		unique[user.User] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for user := range unique {
		result = append(result, user)
	}
	sort.Strings(result)
	return result
}

func collectIPAddresses() []string {
	addrs := []string{}
	interfaces, err := stdnet.Interfaces()
	if err != nil {
		return addrs
	}
	seen := make(map[string]struct{})
	for _, iface := range interfaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifaceAddrs {
			ip, _, err := stdnet.ParseCIDR(addr.String())
			if err != nil || ip == nil || !ip.IsGlobalUnicast() {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			addrs = append(addrs, key)
		}
	}
	sort.Strings(addrs)
	return addrs
}

func collectMACAddresses() []string {
	interfaces, err := stdnet.Interfaces()
	if err != nil {
		return nil
	}
	macs := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.HardwareAddr == nil {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs
}

func collectProcesses(limit int) ([]types.ProcessSnapshot, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	unlimited := limit <= 0
	initialCap := limit
	if unlimited {
		initialCap = len(pids)
	}

	snapshots := make([]types.ProcessSnapshot, 0, initialCap)
	for _, pid := range pids {
		if !unlimited && len(snapshots) >= limit {
			break
		}
		proc, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		name, _ := proc.Name()
		if name == "" {
			name = "unknown"
		}
		cmdline, _ := proc.Cmdline()
		username, _ := proc.Username()
		create, _ := proc.CreateTime()
		ppid, _ := proc.Ppid()
		binaryHash := hashExecutable(proc)

		snapshots = append(snapshots, types.ProcessSnapshot{
			PID:        int(pid),
			ParentPID:  int(ppid),
			Name:       name,
			Command:    cmdline,
			BinaryHash: binaryHash,
			User:       username,
			StartTime:  millisToTime(create),
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].PID < snapshots[j].PID
	})

	return snapshots, nil
}

func hashExecutable(proc *process.Process) string {
	exe, err := proc.Exe()
	if err != nil || exe == "" {
		return ""
	}
	file, err := os.Open(exe)
	if err != nil {
		return ""
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, 5*1024*1024)); err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func millisToTime(ms int64) *time.Time {
	if ms <= 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}

func collectConnections() ([]types.NetworkConnection, error) {
	conns, err := gopsnet.Connections("tcp")
	if err != nil {
		return nil, err
	}

	result := make([]types.NetworkConnection, 0, len(conns))
	for _, conn := range conns {
		nc := types.NetworkConnection{
			Protocol:     "tcp",
			LocalAddress: conn.Laddr.IP,
			LocalPort:    int(conn.Laddr.Port),
			Status:       conn.Status,
		}
		if conn.Raddr.IP != "" {
			nc.RemoteAddress = conn.Raddr.IP
			nc.RemotePort = int(conn.Raddr.Port)
		}
		if conn.Pid != 0 {
			nc.ProcessID = int(conn.Pid)
		}
		result = append(result, nc)
	}
	return result, nil
}

func safeString(value string) string {
	if value == "" {
		return ""
	}
	return value
}
