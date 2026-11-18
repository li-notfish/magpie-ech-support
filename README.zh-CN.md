# magpie-ech-middleware

给 [magpie](https://usemagpie.ai) 用的 DNS over HTTPS（DoH）供应商插件。
sidecar 通过加密 DNS 查询上游的 A/AAAA 地址，再连接返回的 IP 并转发请求。

DoH 加密 DNS 查询；可选 ECH 在上游 HTTPS 记录实际发布配置时加密 TLS SNI。
历史包名、sidecar 名称和 `ech` 供应商 ID 仅为兼容已有安装而保留。

## 安装与登录

```sh
magpie plugin add github:li-notfish/magpie-ech-middleware
```

设置 → 供应商 → **DoH** → 登录，填写上游 HTTPS Base URL、API 类型和 API Key。
可以多次登录，使用不同上游或不同 Key。模型路由仍使用兼容 ID：`ech/<模型>`。
支持 Chat Completions、Responses、Anthropic Messages、Gemini 和流式响应。

修改已有账号时，在供应商编辑器中点该账号的 **编辑**。已保存的地址和 API
类型会预填；密钥留空保持不变，填写新密钥则替换，无需重新登录。保存只影响
当前账号。此功能需要支持可编辑插件账号的 magpie 版本。

## DoH 配置

插件选项在 `plugins.json` 中，可用 `magpie plugin options <名字> '<json>'` 设置：

| 选项 | 默认 | 做什么 |
| --- | --- | --- |
| `port` | `8790` | sidecar 的本地监听端口 |
| `doh` | `""` | DoH 地址，多个用逗号分隔；留空使用内置服务 |
| `ech` | `false` | 自动读取上游 HTTPS 记录中的 ECH 配置，有配置时启用 |

不配置 `doh` 时，并发使用以下两个服务，第一个返回有效地址的答案生效：

```text
https://223.5.5.5/resolve
https://1.12.12.12/dns-query
```

内置服务使用 IP 地址，连接它们本身不需要先做系统 DNS 查询。

### 使用自己的 DoH

```sh
magpie plugin options magpie-ech-middleware '{"doh":"https://doh.pub/dns-query"}'
```

多个地址用逗号分隔，会**替换**而不是追加内置服务：

```sh
magpie plugin options magpie-ech-middleware '{"doh":"https://doh.pub/dns-query,https://dns.alidns.com/dns-query"}'
```

支持 JSON DoH（如 `https://dns.alidns.com/dns-query`）和 RFC 8484 wire
格式（如 `https://doh.pub/dns-query`）。地址必须是实际响应查询的完整 URL，
支持 `https`；`http` 仅建议本机或测试使用，因为它不加密 DNS。

自定义服务的域名可能通过系统 DNS 解析以连接该服务，但所有**上游**域名仍只
通过 DoH 查询。修改 `doh` 后重启 magpie，使 sidecar 使用新配置。

## 可选 ECH

```sh
magpie plugin options magpie-ech-middleware '{"ech":true}'
```

开启后，sidecar 还会通过 DoH 查询上游的 HTTPS（65 型）记录，只使用记录实际
发布的 `ech` 配置，不内置固定 Cloudflare 配置，也不根据托管商猜测。
记录不存在或查询失败时使用普通 TLS；已发布的配置被服务端拒绝时，只使用服务端
返回的新配置重试，不会静默降级为明文 SNI。

设回 `false` 即仅使用 DoH。修改 `doh` 或 `ech` 后重启 magpie，使 sidecar 使用新参数。

## 请求链路

1. 插件把已登录的上游写入
   `<magpie 目录>/magpie-ech-middleware/upstreams.json`。
2. 模型列表或首个请求启动 sidecar，loader 将请求指向本地 sidecar。
3. sidecar 通过 DoH 并发查询上游的 A 和 AAAA 记录，缓存成功答案。
4. sidecar 连接返回的 IP，以原域名完成 TLS 握手。开启 `ech` 且取得实际发布的
   配置时使用 TLS 1.3 ECH 加密 SNI，否则使用普通 TLS。
5. 转发请求与响应（包括 SSE 流式响应）。

上游文件保持简单：

```json
{
  "api-example-com-v1-9f86d081": "https://api.example.com/v1"
}
```

旧文件中的 `{ "url": "...", "ech": "..." }` 可以读取，但 `ech` 会被忽略，
并在该上游下次登录或刷新模型时移除。`echFallback` 插件选项、
`ECH_SIDECAR_ECH_FALLBACK` 和 `ECH_SIDECAR_ALLOW_PLAIN` 已不再使用；不支持手填固定 ECH 配置。
HTTP Host、TLS SNI 和证书校验仍使用原域名。

## 单独运行 sidecar

```sh
ech-sidecar.exe -upstreams-file upstreams.json -listen 127.0.0.1:8790 `
  -doh "https://doh.pub/dns-query" [-ech]
```

省略 `-doh` 即使用内置服务。启动后 stdout 输出一行 JSON：

```json
{"ok":true,"port":8790,"upstreams":{"api-example-com-v1-9f86d081":{"url":"https://api.example.com/v1","doh":true}}}
```

`/_ech/health` 是兼容保留的本地健康检查路径，不访问上游。

## 构建与发布

仓库不附带 sidecar 二进制。首次使用时，插件从
[sidecar 发布](https://github.com/li-notfish/magpie-ech-middleware/releases/tag/sidecar)
下载对应平台和架构的文件，按包版本保存到 magpie 目录。

| 平台 | 附件名 |
| --- | --- |
| Windows x64 / arm64 | `ech-sidecar-win32-x64.exe`、`ech-sidecar-win32-arm64.exe` |
| Linux x64 / arm64 | `ech-sidecar-linux-x64`、`ech-sidecar-linux-arm64` |
| macOS x64 / arm64 | `ech-sidecar-darwin-x64`、`ech-sidecar-darwin-arm64` |

可用 `ECH_SIDECAR_PATH` 指定二进制，或放在 `sidecar/bin/<平台>-<架构>/`。
没有发布附件的平台可以在安装 Go 1.26 或更新版本后从源码构建：

```sh
npm run build
```

修改 `sidecar/` 后必须提升 `package.json` 的 `version`，否则已下载过该版本的
机器不会获取新二进制。

## 排查

- **模型列不出来**：检查上游 HTTPS 地址、API 类型、Key 和模型列表端点；
  旧账号若未保存地址，需要重新登录。
- **ECH 未生效**：开启 `ech`，并确认上游 HTTPS 记录实际包含 `ech`；橙色云本身
  不等于客户端已经取得配置。
- **DoH 解析失败**：确认 `doh` 是完整查询 URL，并检查网络能否访问该服务；
  也可以清空 `doh` 恢复内置服务后重启 magpie。
- **TLS 证书错误**：插件只改变地址解析，不关闭证书校验；请检查上游域名和证书。
- **sidecar 起不来**：检查端口占用；必要时设置 `ECH_SIDECAR_PATH` 或执行
  `npm run build`。
