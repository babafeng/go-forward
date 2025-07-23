# go-forward

A simple traffic forwarding tool

## build

```bash
go build -ldflags="-s -w"
```

## Intranet Reverse Tunnel

Server

```bash
go-forward -L 7000 -H YOUR.SERVER.COM
```

You can get CERT text in command output text:

```log
2025/07/01 21:35:09 main.go:291: All configured services started. Running indefinitely...
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJiekNDQVJTZ0F3SUJBZ0lRZDJzb1ZxWTFJWDBpZDlDdjg0NEtPakFLQmdncWhrak9QUVFEQWpBVE1SRXcKRHdZRFZRUURFd2d6TnpRNUxuaHBiakFlRncweU5UQTNNREV4TXpNMU1EbGFGdzB5TmpBM01ERXhNek0xTURsYQpNQk14RVRBUEJnTlZCQU1UQ0RNM05Ea3VlR2x1TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFCkxYZmlYTDVkZzZjYllxSk9KRzVhWVp0aTRNUnB1VmJhaUEvSSt6MTg4NlpjTVVvTGxvVnRyajNBMFU3VzQ3OUcKUzN4VXRlcGF5cWgyR2JwaGFKM1ozS05LTUVnd0RnWURWUjBQQVFIL0JBUURBZ1dnTUJNR0ExVWRKUVFNTUFvRwpDQ3NHQVFVRkJ3TUJNQXdHQTFVZEV3RUIvd1FDTUFBd0V3WURWUjBSQkF3d0NvSUlNemMwT1M1NGFXNHdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU1hWUV0UnlPc3RqcnFwSzBQZU5jTFFFaVpERFVpd1ZNWk54ZzVKSW44ZWsKQWlFQXdpWTNjY2g1b0VhbTFxei9mNk5rRHNXSkJkWGZHNTVNUUgybEptMXh2YzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
2025/07/01 21:35:09 reverse.go:36: Starting server control plane on YOUR.SERVER.COM:7000
```

Client

```bash
go-forward -L 1000//127.0.0.1:1080 -F your.server.com:7000 -C YOUR-CERT-TEXT
```

## Local Proxy

Supports HTTP and SOCKS5 proxies

```bash
go-forward -L http://0.0.0.0:1080
go-forward -L http://username:password@0.0.0.0:1080

go-forward -L socks5://0.0.0.0:1080
go-forward -L socks5://username:password@0.0.0.0:1080
```

## Local TCP traffic forward

Listen on port 1000 and forward traffic to 10.0.0.1:1080

```bash
go-forward -L 1000//10.0.0.1:1080
```

Listen on port 1000-1005 and forward traffic to 10.0.0.1:1000-1005

```bash
go-forward -L 1000-1005//10.0.0.1:1000-1005
```


## Use tips

While starting the proxy locally, forward the proxy port to the remote port

```bash
go-forward -L http://127.0.0.1:1080 -L 2020//127.0.0.1:1080 -F your.server.com:7000
```

Start HTTP and SOCKS5 proxy locally at the same time

```bash
go-forward -L http://0.0.0.0:1080 -L socks5://0.0.0.0:1080

go-forward -L http://0.0.0.0:1080 -L socks5://0.0.0.0:1081 -L 1000//127.0.0.1:1080 -L 1001//127.0.0.1:1081 -F your.server.com:7000
```

The same server supports multiple intranet clients

```bash
# Intranet Host 1:
go-forward -L 1000//127.0.0.1:1080 -F your.server.com:7000

# Intranet Host 2:
go-forward -L 1001//127.0.0.1:1080 -F your.server.com:7000

# Intranet Host 3:
go-forward -L 1002//127.0.0.1:1080 -F your.server.com:7000

...
```

Taking macOS as an example, you can set an alias IP for the loopback address, such as 10.0.0.2 (assuming it is an intranet address and there is no local routing). Then access port 22 of 10.0.0.2 and forward the traffic to proxy 22.

```bash
sudo ifconfig lo0 alias 10.0.0.2 up
go-forward -L 2222//proxy.com:2222
```

```bash
go run . -L https://admin:admin@0.0.0.0:10000 -H 127.0.0.1
go run . -L http://user:pass@0.0.0.0:1000 -F tls://admin:admin@127.0.0.1:10000 -C YOUR-CERT-TEXT

```
