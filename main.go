// Package main 提供基于 mDNS/DNS-SD 的局域网资产发现命令行程序。
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// cliConfig 保存命令行解析后的扫描配置。
type cliConfig struct {
	cidrText  string
	portsText string
	timeout   time.Duration
	iface     string
	json      bool
}

func main() {
	config := cliConfig{}
	flag.StringVar(&config.cidrText, "cidr", "", "结果 IP 过滤网段，例如 192.168.1.0/24")
	flag.StringVar(&config.portsText, "ports", "", "服务端口范围，例如 1-1024,5000,548")
	flag.DurationVar(&config.timeout, "timeout", 5*time.Second, "mDNS 发现窗口")
	flag.StringVar(&config.iface, "iface", "", "指定网络接口，默认所有可用组播接口")
	flag.BoolVar(&config.json, "json", false, "以 JSON 输出")
	flag.Parse()

	if err := run(config); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

// run 校验输入、发起发现并输出最终资产结果。
func run(config cliConfig) error {
	if config.cidrText == "" || config.portsText == "" {
		return errors.New("--cidr 和 --ports 为必填参数")
	}
	if config.timeout <= 0 {
		return errors.New("--timeout 必须大于 0")
	}

	prefix, err := netip.ParsePrefix(config.cidrText)
	if err != nil {
		return fmt.Errorf("无效的 --cidr: %w", err)
	}
	portRanges, err := parsePortRanges(config.portsText)
	if err != nil {
		return err
	}

	assets, err := Scan(Options{CIDR: prefix.Masked(), Ports: portRanges, Timeout: config.timeout, Interface: config.iface})
	if err != nil {
		return err
	}
	if config.json {
		return writeJSON(os.Stdout, assets)
	}
	writeText(os.Stdout, assets)
	return nil
}

// parsePortRanges 解析单端口和闭区间组成的端口表达式。
func parsePortRanges(text string) ([]PortRange, error) {
	parts := strings.Split(text, ",")
	ranges := make([]PortRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("--ports 中存在空端口项")
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("无效端口项 %q", part)
		}
		start, err := strconv.ParseUint(bounds[0], 10, 16)
		if err != nil || start == 0 {
			return nil, fmt.Errorf("无效端口项 %q", part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.ParseUint(bounds[1], 10, 16)
			if err != nil || end == 0 || start > end {
				return nil, fmt.Errorf("无效端口范围 %q", part)
			}
		}
		ranges = append(ranges, PortRange{Start: uint16(start), End: uint16(end)})
	}
	return ranges, nil
}
