package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	serviceEnumerator = "_services._dns-sd._udp.local."
	mdnsPort          = 5353
)

// Options 定义一次 mDNS 发现任务的网络与过滤条件。
type Options struct {
	CIDR      netip.Prefix
	Ports     []PortRange
	Timeout   time.Duration
	Interface string
}

// recordCache 保存同一发现窗口中收到的 DNS 资源记录及其关联索引。
type recordCache struct {
	mu           sync.Mutex
	serviceTypes map[string]struct{}
	instances    map[string][]string
	srvs         map[string]srvRecord
	txts         map[string][]string
	txtTTL       map[string]uint32
	ptrTTL       map[string]uint32
	hosts        map[string]hostAddresses
}

// srvRecord 保存服务实例指向的主机、端口和缓存时间。
type srvRecord struct {
	Target string
	Port   uint16
	TTL    uint32
}

// hostAddresses 保存同一 mDNS 主机的 IPv4 与 IPv6 地址。
type hostAddresses struct {
	v4 []netip.Addr
	v6 []netip.Addr
}

func (addresses hostAddresses) matchPrefix(prefix netip.Prefix) bool {
	for _, address := range addresses.v4 {
		if prefix.Contains(address) {
			return true
		}
	}
	for _, address := range addresses.v6 {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (addresses hostAddresses) ipv4() []string { return addressesToStrings(addresses.v4) }
func (addresses hostAddresses) ipv6() []string { return addressesToStrings(addresses.v6) }

func addressesToStrings(addresses []netip.Addr) []string {
	result := make([]string, len(addresses))
	for index, address := range addresses {
		result[index] = address.String()
	}
	sort.Strings(result)
	return result
}

// listener 绑定一个组播连接及其对应的发送目标。
type listener struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

// Scan 在本机可用接口上发现 mDNS 服务，并按 CIDR、端口范围生成资产。
func Scan(options Options) ([]Asset, error) {
	interfaces, err := eligibleInterfaces(options.Interface)
	if err != nil {
		return nil, err
	}
	listeners := openListeners(interfaces)
	if len(listeners) == 0 {
		return nil, errors.New("无法监听 mDNS 5353 端口，请检查接口、权限或本机 mDNS 服务")
	}

	cache := newRecordCache()
	var readers sync.WaitGroup
	for _, socket := range listeners {
		readers.Add(1)
		go readResponses(socket.conn, cache, &readers)
	}

	deadline := time.Now().Add(options.Timeout)
	queryAll(listeners, serviceEnumerator, dns.TypePTR)
	waitUntil(deadline, options.Timeout/4)
	for _, serviceType := range cache.snapshotServiceTypes() {
		queryAll(listeners, serviceType, dns.TypePTR)
	}
	waitUntil(deadline, options.Timeout/4)
	for _, instance := range cache.snapshotInstances() {
		queryAll(listeners, instance, dns.TypeSRV)
		queryAll(listeners, instance, dns.TypeTXT)
	}
	waitUntil(deadline, options.Timeout/5)
	for _, target := range cache.snapshotTargets() {
		queryAll(listeners, target, dns.TypeA)
		queryAll(listeners, target, dns.TypeAAAA)
	}
	waitUntil(deadline, time.Until(deadline))
	for _, socket := range listeners {
		_ = socket.conn.Close()
	}
	readers.Wait()
	return assetsFromCache(cache, options.CIDR, options.Ports), nil
}

// eligibleInterfaces 返回指定接口或所有已启用且支持组播的非回环接口。
func eligibleInterfaces(name string) ([]net.Interface, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("查找接口 %q: %w", name, err)
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			return nil, fmt.Errorf("接口 %q 未启用或不支持组播", name)
		}
		return []net.Interface{*iface}, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("枚举网络接口: %w", err)
	}
	result := make([]net.Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 && iface.Flags&net.FlagLoopback == 0 {
			result = append(result, iface)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("未找到已启用的组播网络接口")
	}
	return result, nil
}

// openListeners 为每个接口建立可用的 IPv4、IPv6 mDNS 监听套接字。
func openListeners(interfaces []net.Interface) []listener {
	result := make([]listener, 0, len(interfaces)*2)
	for _, iface := range interfaces {
		ipv4Address := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: mdnsPort}
		if conn, err := net.ListenMulticastUDP("udp4", &iface, ipv4Address); err == nil {
			_ = conn.SetReadBuffer(65535)
			result = append(result, listener{conn: conn, addr: ipv4Address})
		}
		ipv6Address := &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: mdnsPort, Zone: iface.Name}
		if conn, err := net.ListenMulticastUDP("udp6", &iface, ipv6Address); err == nil {
			_ = conn.SetReadBuffer(65535)
			result = append(result, listener{conn: conn, addr: ipv6Address})
		}
	}
	return result
}

// queryAll 在所有监听接口上发送同一个 mDNS 问题。
func queryAll(listeners []listener, name string, recordType uint16) {
	message := new(dns.Msg)
	message.Id = 0
	message.RecursionDesired = false
	message.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: recordType, Qclass: dns.ClassINET}}
	payload, err := message.Pack()
	if err != nil {
		return
	}
	for _, socket := range listeners {
		_, _ = socket.conn.WriteToUDP(payload, socket.addr)
	}
}

func readResponses(conn *net.UDPConn, cache *recordCache, readers *sync.WaitGroup) {
	defer readers.Done()
	buffer := make([]byte, 65535)
	for {
		count, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		message := new(dns.Msg)
		if err := message.Unpack(buffer[:count]); err == nil && message.Response {
			cache.addMessage(message)
		}
	}
}

func waitUntil(deadline time.Time, duration time.Duration) {
	if duration <= 0 {
		return
	}
	target := time.Now().Add(duration)
	if target.After(deadline) {
		target = deadline
	}
	if remaining := time.Until(target); remaining > 0 {
		time.Sleep(remaining)
	}
}

func newRecordCache() *recordCache {
	return &recordCache{
		serviceTypes: make(map[string]struct{}),
		instances:    make(map[string][]string),
		srvs:         make(map[string]srvRecord),
		txts:         make(map[string][]string),
		txtTTL:       make(map[string]uint32),
		ptrTTL:       make(map[string]uint32),
		hosts:        make(map[string]hostAddresses),
	}
}

// addMessage 将 DNS 响应的全部资源记录区加入缓存，并去除重复记录。
func (cache *recordCache) addMessage(message *dns.Msg) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	records := append(append(message.Answer, message.Ns...), message.Extra...)
	for _, record := range records {
		header := record.Header()
		name := canonicalName(header.Name)
		switch value := record.(type) {
		case *dns.PTR:
			target := canonicalName(value.Ptr)
			if name == serviceEnumerator {
				cache.serviceTypes[target] = struct{}{}
			} else {
				cache.serviceTypes[name] = struct{}{}
				cache.instances[name] = appendUnique(cache.instances[name], target)
				cache.ptrTTL[target] = header.Ttl
			}
		case *dns.SRV:
			cache.srvs[name] = srvRecord{Target: canonicalName(value.Target), Port: value.Port, TTL: header.Ttl}
		case *dns.TXT:
			cache.txts[name] = appendUniqueMany(cache.txts[name], value.Txt)
			cache.txtTTL[name] = header.Ttl
		case *dns.A:
			if address, ok := netip.AddrFromSlice(value.A); ok {
				host := cache.hosts[name]
				host.v4 = appendAddressUnique(host.v4, address.Unmap())
				cache.hosts[name] = host
			}
		case *dns.AAAA:
			if address, ok := netip.AddrFromSlice(value.AAAA); ok {
				host := cache.hosts[name]
				host.v6 = appendAddressUnique(host.v6, address)
				cache.hosts[name] = host
			}
		}
	}
}

func (cache *recordCache) snapshotServiceTypes() []string {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return sortedKeys(cache.serviceTypes)
}

func (cache *recordCache) snapshotInstances() []string {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	set := make(map[string]struct{})
	for _, instances := range cache.instances {
		for _, instance := range instances {
			set[instance] = struct{}{}
		}
	}
	return sortedKeys(set)
}

func (cache *recordCache) snapshotTargets() []string {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	set := make(map[string]struct{})
	for _, srv := range cache.srvs {
		set[srv.Target] = struct{}{}
	}
	return sortedKeys(set)
}

func canonicalName(name string) string { return strings.ToLower(dns.Fqdn(name)) }

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueMany(values, additions []string) []string {
	for _, addition := range additions {
		values = appendUnique(values, addition)
	}
	return values
}

func appendAddressUnique(values []netip.Addr, value netip.Addr) []netip.Addr {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
