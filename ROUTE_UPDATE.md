# Go-Forward Route 模块更新说明

## 新增功能

### 1. SOCKS5 UDP 支持

现在 SOCKS5 代理完全支持 UDP ASSOCIATE 命令,可以处理 UDP 流量,例如:
- NTP (Network Time Protocol) - 端口 123
- DNS 查询
- 其他 UDP 应用

**工作原理:**
- SOCKS5 服务器在 TCP 端口上接受 UDP ASSOCIATE 请求
- 使用相同的端口号监听 UDP 流量
- 自动转发 UDP 数据包到目标服务器
- 支持 IPv4、IPv6 和域名地址

### 2. 统一代理模式 (Unified Proxy)

**最大的新特性!** 现在可以在**同一个端口**同时支持 HTTP 和 SOCKS5 协议!

**配置方法:**

```ini
[General]
# 使用统一代理模式 - 一个端口同时支持 HTTP 和 SOCKS5
unified-listen = 127.0.0.1:1080
```

**优势:**
- ✅ 只需要一个端口
- ✅ 自动检测协议类型(HTTP 或 SOCKS5)
- ✅ 同时支持 HTTP CONNECT、HTTP 转发、SOCKS5 TCP 和 SOCKS5 UDP
- ✅ 简化配置和防火墙规则

**传统分离模式:**

如果你仍然想使用分离的端口,可以这样配置:

```ini
[General]
http-listen = 127.0.0.1:1080
socks5-listen = 127.0.0.1:1081
```

### 3. 增强的日志输出

现在日志会显示更详细的信息:
- 客户端地址
- 使用的上游代理
- 协议类型(HTTP/SOCKS5/UDP)
- 目标地址和端口
- 匹配的路由规则

**示例日志:**

```
2025-11-25 10:43:07 routing: PROXY1 http 192.168.1.100:54321 --> google.com:443 [action=PROXY matched=true rule_type=DOMAIN-KEYWORD rule_value=google]
2025-11-25 10:43:08 routing: None socks5 --> time.apple.com:123 [action=DIRECT matched=false]
2025-11-25 10:43:09 udp relay: 192.168.1.100:54322 -> time.windows.com:123 (48 bytes)
```

## 使用示例

### 启动统一代理服务器

```bash
# 使用默认配置(~/.forward/proxy-config.conf)
go-forward

# 使用自定义配置
go-forward -R /path/to/config.conf
```

### 客户端配置

**浏览器/系统代理设置:**
- HTTP 代理: 127.0.0.1:1080
- HTTPS 代理: 127.0.0.1:1080
- SOCKS5 代理: 127.0.0.1:1080

**所有协议都使用同一个端口!**

### 测试 UDP 功能

```bash
# 使用 curl 通过 SOCKS5 代理访问(会自动处理 DNS UDP 查询)
curl --socks5 127.0.0.1:1080 http://example.com

# 测试 NTP(需要支持 SOCKS5 的 NTP 客户端)
# 系统的 NTP 客户端会自动使用代理(如果配置了系统代理)
```

## 配置文件示例

查看 `example-config.conf` 获取完整的配置示例。

## 技术细节

### 协议检测

统一代理服务器通过检查连接的第一个字节来区分协议:
- `0x05` = SOCKS5 协议
- ASCII 字母 (G, P, C, etc.) = HTTP 协议

### UDP 转发流程

1. 客户端发送 SOCKS5 UDP ASSOCIATE 请求(TCP)
2. 服务器返回 UDP 中继地址
3. 客户端发送 UDP 数据包到中继地址
4. 服务器解析 SOCKS5 UDP 包头,提取目标地址
5. 服务器转发数据到目标服务器
6. 服务器接收响应并封装成 SOCKS5 UDP 格式
7. 服务器发送响应回客户端

### 路由决策

所有流量(HTTP、SOCKS5 TCP、SOCKS5 UDP)都使用相同的路由规则:
- DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD
- IP-CIDR
- GEOIP
- FINAL

## 故障排除

### UDP 流量不工作

1. 确保防火墙允许 UDP 流量
2. 检查上游代理是否支持 UDP
3. 查看日志中的 "udp relay" 消息

### 协议检测失败

如果统一代理无法正确识别协议,可以切换回分离模式:
```ini
http-listen = 127.0.0.1:1080
socks5-listen = 127.0.0.1:1081
```

### 性能问题

统一代理模式的性能开销非常小(只需要读取第一个字节),但如果遇到问题,可以:
1. 使用分离模式
2. 增加系统文件描述符限制
3. 调整超时设置

## 未来计划

- [ ] UDP 转发性能优化
- [ ] 支持 SOCKS5 BIND 命令
- [ ] WebSocket 代理支持
- [ ] 更多的路由规则类型
