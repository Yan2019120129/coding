# mdnsmap

`mdnsmap` 是一个使用 Go 编写的局域网 mDNS/DNS-SD 资产发现 CLI。它从 PTR、SRV、TXT、A 和 AAAA 记录中关联出主机、地址、服务端口与完整 TXT banner，适合在已获授权的本地网络中进行资产盘点。

## 能力

- 通过 `_services._dns-sd._udp.local.` 自动枚举服务类型；
- 识别服务实例、TCP/UDP 端口、主机名、IPv4、IPv6 和 TTL；
- 完整保留 TXT 字段，可识别 `path`、设备型号、固件版本及厂商扩展属性；
- 支持 CIDR、多个端口或端口范围过滤；
- 支持可读文本和 JSON 输出；
- 同时监听可用接口上的 IPv4 与 IPv6 mDNS 组播。

## 安装

```bash
go build -o mdnsmap .
```

## 使用

```bash
./mdnsmap --cidr 192.168.1.0/24 --ports 1-65535 --timeout 5s
./mdnsmap --cidr 192.168.1.0/24 --ports 9,445,548,5000 --json
./mdnsmap --cidr fe80::/10 --ports 1-65535 --iface eth0
```

参数说明：

| 参数 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--cidr` | 是 | - | 只输出至少一个地址落入该网段的资产 |
| `--ports` | 是 | - | SRV 主端口过滤，支持 `80,443,8000-9000` |
| `--timeout` | 否 | `5s` | 完整发现窗口 |
| `--iface` | 否 | 全部可用接口 | 指定组播网络接口 |
| `--json` | 否 | `false` | 输出 JSON |

## 输出示例

```text
asset:
Hostname=slw-nas.local
IPv4=192.168.1.20
IPv6=fe80::265e:beff:fe69:a313
services:
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.20
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https
accessPort=86
model=TS-X64
displayModel=TS-464C
fwVer=5.2.9
fwBuildNum=20260214
answers:
PTR:
_qdiscover._tcp.local.
```

## 协议边界

mDNS 使用链路本地组播地址 `224.0.0.251` 和 `ff02::fb` 的 UDP 5353 端口，通常不会被路由器转发。因此 `--cidr` 用来过滤本地链路发现结果，并不表示能够扫描任意远程网段。TXT 中出现的 `accessPort` 等派生端口属于 banner，仍会保留，但不会参与 `--ports` 的 SRV 主端口过滤。

## 测试

```bash
go test ./...
go test -race ./...
```
