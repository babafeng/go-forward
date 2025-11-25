#!/bin/bash

echo "=== Go-Forward 统一代理测试 ==="
echo ""

# 检查是否已编译
if [ ! -f "./go-forward" ]; then
    echo "编译 go-forward..."
    go build -o go-forward
fi

# 创建测试配置
cat > /tmp/test-proxy-config.conf << 'EOF'
[General]
unified-listen = 127.0.0.1:10800
log-level = info
log-format = text
default-proxy = DIRECT

[Proxy]

[Rule]
FINAL,DIRECT
EOF

echo "✓ 创建测试配置: /tmp/test-proxy-config.conf"
echo "✓ 统一代理端口: 127.0.0.1:10800"
echo ""
echo "启动代理服务器..."
echo "----------------------------------------"
echo ""

# 启动代理
./go-forward -R /tmp/test-proxy-config.conf

# 清理
rm -f /tmp/test-proxy-config.conf
