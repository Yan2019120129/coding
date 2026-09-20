package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParsePortRanges(t *testing.T) {
	ranges, err := parsePortRanges("9,445,5000-5001")
	if err != nil {
		t.Fatalf("解析端口范围失败: %v", err)
	}
	if len(ranges) != 3 || !ranges[2].Contains(5001) || ranges[2].Contains(5002) {
		t.Fatalf("端口范围解析结果不符合预期: %#v", ranges)
	}
	for _, invalid := range []string{"", "0", "100-10", "65536", "80,", "80abc", "1-2-3"} {
		if _, err := parsePortRanges(invalid); err == nil {
			t.Errorf("无效输入 %q 应返回错误", invalid)
		}
	}
}

func TestAssetsFromCacheDeepBanner(t *testing.T) {
	cache := newRecordCache()
	message := new(dns.Msg)
	message.Response = true
	message.Answer = mustRecords(t,
		"_services._dns-sd._udp.local. 10 IN PTR _workstation._tcp.local.",
		"_services._dns-sd._udp.local. 10 IN PTR _http._tcp.local.",
		"_services._dns-sd._udp.local. 10 IN PTR _smb._tcp.local.",
		"_services._dns-sd._udp.local. 10 IN PTR _qdiscover._tcp.local.",
		"_services._dns-sd._udp.local. 10 IN PTR _device-info._tcp.local.",
		"_services._dns-sd._udp.local. 10 IN PTR _afpovertcp._tcp.local.",
		"_workstation._tcp.local. 10 IN PTR slw-nas\\032[24:5e:be:69:a3:13]._workstation._tcp.local.",
		"_http._tcp.local. 10 IN PTR slw-nas._http._tcp.local.",
		"_smb._tcp.local. 10 IN PTR slw-nas._smb._tcp.local.",
		"_qdiscover._tcp.local. 10 IN PTR slw-nas._qdiscover._tcp.local.",
		"_device-info._tcp.local. 10 IN PTR slw-nas\\(AFP\\)._device-info._tcp.local.",
		"_afpovertcp._tcp.local. 10 IN PTR slw-nas\\(AFP\\)._afpovertcp._tcp.local.",
		"slw-nas\\032[24:5e:be:69:a3:13]._workstation._tcp.local. 10 IN SRV 0 0 9 slw-nas.local.",
		"slw-nas._http._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local.",
		"slw-nas._smb._tcp.local. 10 IN SRV 0 0 445 slw-nas.local.",
		"slw-nas._qdiscover._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local.",
		"slw-nas\\(AFP\\)._afpovertcp._tcp.local. 10 IN SRV 0 0 548 slw-nas.local.",
		"slw-nas._http._tcp.local. 10 IN TXT \"path=/\"",
		"slw-nas._qdiscover._tcp.local. 10 IN TXT \"accessType=https\" \"accessPort=86\" \"model=TS-X64\" \"displayModel=TS-464C\" \"fwVer=5.2.9\" \"fwBuildNum=20260214\"",
		"slw-nas\\(AFP\\)._device-info._tcp.local. 10 IN TXT \"model=Xserve\"",
		"slw-nas.local. 10 IN A 192.168.50.20",
		"slw-nas.local. 10 IN AAAA fe80::265e:beff:fe69:a313",
	)
	cache.addMessage(message)

	assets := assetsFromCache(cache, netip.MustParsePrefix("192.168.50.0/24"), []PortRange{{Start: 1, End: 6000}})
	if len(assets) != 1 {
		t.Fatalf("期望得到 1 个资产，实际为 %d", len(assets))
	}
	asset := assets[0]
	if asset.Hostname != "slw-nas.local" || len(asset.IP) != 2 || len(asset.Services) != 6 {
		t.Fatalf("资产关联不完整: %#v", asset)
	}
	assertServiceBanner(t, asset.Services, "_qdiscover._tcp.local.", "fwBuildNum=20260214")
	assertServiceBanner(t, asset.Services, "_device-info._tcp.local.", "model=Xserve")

	var output bytes.Buffer
	writeText(&output, assets)
	for _, expected := range []string{
		"9/tcp workstation:", "5000/tcp http:", "445/tcp smb:",
		"5000/tcp qdiscover:", "device-info:", "548/tcp afpovertcp:",
		"IPv4=192.168.50.20", "IPv6=fe80::265e:beff:fe69:a313", "path=/",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("文本输出缺少 %q\n%s", expected, output.String())
		}
	}

	output.Reset()
	if err := writeJSON(&output, assets); err != nil {
		t.Fatalf("输出 JSON 失败: %v", err)
	}
	for _, expected := range []string{`"ip"`, `"host"`, `"port"`, `"banner"`, `"fwBuildNum=20260214"`} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("JSON 输出缺少 %q\n%s", expected, output.String())
		}
	}
}

func TestAssetsFromCacheFiltersPortAndCIDR(t *testing.T) {
	cache := newRecordCache()
	message := new(dns.Msg)
	message.Response = true
	message.Answer = mustRecords(t,
		"_http._tcp.local. 10 IN PTR web._http._tcp.local.",
		"web._http._tcp.local. 10 IN SRV 0 0 8080 web.local.",
		"web.local. 10 IN A 10.0.0.8",
	)
	cache.addMessage(message)
	if assets := assetsFromCache(cache, netip.MustParsePrefix("10.0.1.0/24"), []PortRange{{Start: 8080, End: 8080}}); len(assets) != 0 {
		t.Fatalf("CIDR 不匹配时不应输出资产: %#v", assets)
	}
	if assets := assetsFromCache(cache, netip.MustParsePrefix("10.0.0.0/24"), []PortRange{{Start: 80, End: 80}}); len(assets) != 0 {
		t.Fatalf("端口不匹配时不应输出资产: %#v", assets)
	}
}

func mustRecords(t *testing.T, records ...string) []dns.RR {
	t.Helper()
	result := make([]dns.RR, 0, len(records))
	for _, text := range records {
		record, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("构造 DNS 记录 %q: %v", text, err)
		}
		result = append(result, record)
	}
	return result
}

func assertServiceBanner(t *testing.T, services []Service, serviceType, banner string) {
	t.Helper()
	for _, service := range services {
		if service.Type == serviceType && strings.Contains(strings.Join(service.Banner, ","), banner) {
			return
		}
	}
	t.Errorf("服务 %s 缺少 banner %q: %#v", serviceType, banner, services)
}
