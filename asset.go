package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// PortRange 表示包含起止端点的服务端口范围。
type PortRange struct {
	Start uint16
	End   uint16
}

// Contains 判断端口是否处于当前范围内。
func (portRange PortRange) Contains(port uint16) bool {
	return port >= portRange.Start && port <= portRange.End
}

// Asset 表示按 mDNS 主机名聚合后的网络资产。
type Asset struct {
	IP       []string  `json:"ip"`
	Hostname string    `json:"host"`
	IPv4     []string  `json:"ipv4,omitempty"`
	IPv6     []string  `json:"ipv6,omitempty"`
	Services []Service `json:"services"`
	PTR      []string  `json:"ptr_answers"`
}

// Service 表示 DNS-SD 服务以及从 TXT 记录获得的识别信息。
type Service struct {
	Type     string   `json:"type"`
	Instance string   `json:"instance"`
	Port     uint16   `json:"port,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	TTL      uint32   `json:"ttl"`
	Banner   []string `json:"banner,omitempty"`
	HasSRV   bool     `json:"has_srv"`
}

// writeJSON 以稳定缩进格式输出资产，便于其他程序消费。
func writeJSON(writer io.Writer, assets []Asset) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(assets)
}

// writeText 输出接近常见 mDNS 浏览器风格的可读报告。
func writeText(writer io.Writer, assets []Asset) {
	if len(assets) == 0 {
		fmt.Fprintln(writer, "未发现匹配的 mDNS 资产")
		return
	}
	for index, asset := range assets {
		if index > 0 {
			fmt.Fprintln(writer)
		}
		fmt.Fprintln(writer, "asset:")
		fmt.Fprintf(writer, "Hostname=%s\n", asset.Hostname)
		writeAddresses(writer, asset)
		fmt.Fprintln(writer, "services:")
		for _, service := range asset.Services {
			if service.HasSRV {
				fmt.Fprintf(writer, "%d/%s %s:\n", service.Port, service.Protocol, serviceName(service.Type))
			} else {
				fmt.Fprintf(writer, "%s:\n", serviceName(service.Type))
			}
			fmt.Fprintf(writer, "Name=%s\n", service.Instance)
			writeAddresses(writer, asset)
			fmt.Fprintf(writer, "Hostname=%s\nTTL=%d\n", asset.Hostname, service.TTL)
			for _, banner := range service.Banner {
				fmt.Fprintln(writer, banner)
			}
		}
		fmt.Fprintln(writer, "answers:")
		fmt.Fprintln(writer, "PTR:")
		for _, ptr := range asset.PTR {
			fmt.Fprintln(writer, ptr)
		}
	}
}

func writeAddresses(writer io.Writer, asset Asset) {
	for _, ip := range asset.IPv4 {
		fmt.Fprintf(writer, "IPv4=%s\n", ip)
	}
	for _, ip := range asset.IPv6 {
		fmt.Fprintf(writer, "IPv6=%s\n", ip)
	}
}

// assetsFromCache 将分散的 DNS 记录关联为通过 CIDR 和端口筛选的资产列表。
func assetsFromCache(cache *recordCache, prefix netip.Prefix, ranges []PortRange) []Asset {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	assets := make(map[string]*Asset)
	serviceTypes := sortedKeys(cache.instances)
	for _, serviceType := range serviceTypes {
		for _, instance := range cache.instances[serviceType] {
			srv, hasSRV := cache.srvs[instance]
			if !hasSRV || !portAllowed(srv.Port, ranges) {
				continue
			}
			addresses := cache.hosts[srv.Target]
			if !addresses.matchPrefix(prefix) {
				continue
			}
			asset := assets[srv.Target]
			if asset == nil {
				allAddresses := append(addresses.ipv4(), addresses.ipv6()...)
				asset = &Asset{
					IP:       allAddresses,
					Hostname: displayHostname(srv.Target),
					IPv4:     addresses.ipv4(),
					IPv6:     addresses.ipv6(),
				}
				assets[srv.Target] = asset
			}
			asset.Services = append(asset.Services, Service{
				Type:     serviceType,
				Instance: displayInstance(instance, serviceType),
				Port:     srv.Port,
				Protocol: protocolFromType(serviceType),
				TTL:      minimumTTL(srv.TTL, cache.txtTTL[instance]),
				Banner:   append([]string(nil), cache.txts[instance]...),
				HasSRV:   true,
			})
		}
	}

	// 某些设备仅为 device-info 发布 PTR/TXT，按实例显示名与已识别主机进行保守关联。
	for _, serviceType := range serviceTypes {
		for _, instance := range cache.instances[serviceType] {
			if _, hasSRV := cache.srvs[instance]; hasSRV {
				continue
			}
			for _, asset := range assets {
				if identity(displayInstance(instance, serviceType)) != identity(hostLabel(asset.Hostname)) {
					continue
				}
				asset.Services = append(asset.Services, Service{
					Type:     serviceType,
					Instance: displayInstance(instance, serviceType),
					TTL:      minimumTTL(cache.ptrTTL[instance], cache.txtTTL[instance]),
					Banner:   append([]string(nil), cache.txts[instance]...),
				})
				break
			}
		}
	}

	result := make([]Asset, 0, len(assets))
	for _, asset := range assets {
		ptrSet := make(map[string]struct{}, len(asset.Services))
		for _, service := range asset.Services {
			ptrSet[service.Type] = struct{}{}
		}
		asset.PTR = sortedKeys(ptrSet)
		sort.Slice(asset.Services, func(i, j int) bool {
			if asset.Services[i].HasSRV != asset.Services[j].HasSRV {
				return asset.Services[i].HasSRV
			}
			if asset.Services[i].Port != asset.Services[j].Port {
				return asset.Services[i].Port < asset.Services[j].Port
			}
			return asset.Services[i].Type < asset.Services[j].Type
		})
		result = append(result, *asset)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Hostname < result[j].Hostname })
	return result
}

func portAllowed(port uint16, ranges []PortRange) bool {
	for _, portRange := range ranges {
		if portRange.Contains(port) {
			return true
		}
	}
	return false
}

func serviceName(serviceType string) string {
	labels := strings.Split(strings.TrimSuffix(serviceType, "."), ".")
	if len(labels) == 0 {
		return serviceType
	}
	return strings.TrimPrefix(labels[0], "_")
}

func protocolFromType(serviceType string) string {
	for _, label := range strings.Split(serviceType, ".") {
		if label == "_tcp" {
			return "tcp"
		}
		if label == "_udp" {
			return "udp"
		}
	}
	return "unknown"
}

func displayHostname(name string) string {
	return unescapeDNSName(strings.TrimSuffix(name, "."))
}

func displayInstance(instance, serviceType string) string {
	return unescapeDNSName(strings.TrimSuffix(strings.TrimSuffix(instance, serviceType), "."))
}

func hostLabel(hostname string) string {
	return strings.Split(strings.TrimSuffix(hostname, "."), ".")[0]
}

func identity(value string) string {
	value = strings.ToLower(value)
	if index := strings.Index(value, "["); index >= 0 {
		value = value[:index]
	}
	if index := strings.Index(value, "("); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

// unescapeDNSName 将 DNS 展示格式中的反斜杠和三位十进制转义恢复为原始字符。
func unescapeDNSName(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' || index+1 >= len(value) {
			builder.WriteByte(value[index])
			continue
		}
		if index+3 < len(value) && isDigit(value[index+1]) && isDigit(value[index+2]) && isDigit(value[index+3]) {
			number := int(value[index+1]-'0')*100 + int(value[index+2]-'0')*10 + int(value[index+3]-'0')
			if number <= 255 {
				builder.WriteByte(byte(number))
				index += 3
				continue
			}
		}
		builder.WriteByte(value[index+1])
		index++
	}
	return builder.String()
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func minimumTTL(first, second uint32) uint32 {
	if first == 0 {
		return second
	}
	if second == 0 || first < second {
		return first
	}
	return second
}
