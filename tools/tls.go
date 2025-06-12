package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

var (
	CertCache      = make(map[string]tls.Certificate)
	CertCacheMutex sync.Mutex
)

// GenerateSelfSignedCert 根据传入的域名或 IP 生成一个自签名证书 (使用 ECDSA P-256)
func GenerateSelfSignedCert(host string) ([]byte, []byte) {
	// 生成 ECDSA P-256 私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// 设置证书有效期（当前到 1 年后）
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// 生成一个随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	// 配置证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 根据 host 判断是 IP 地址还是 DNS 名称
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// 根据模板生成证书，注意此处自签名，故使用同一个模板做签名和被签名对象
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	// 将生成的证书和私钥编码为 PEM 格式
	cert, key := pemEncode(derBytes, priv)
	return cert, key
}

// pemEncode 将 DER 格式的数据编码为 PEM 格式 (包私有)
func pemEncode(derBytes []byte, key *ecdsa.PrivateKey) ([]byte, []byte) {
	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		// 实践中，这里应该返回错误而不是 panic，或者记录错误
		// 为了简洁，这里暂时忽略错误处理的细节，但在生产代码中很重要
		panic(fmt.Sprintf("无法序列化 ECDSA 私钥: %v", err))
	}
	keyPemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	certPEM := pem.EncodeToMemory(certPemBlock)
	keyPEM := pem.EncodeToMemory(keyPemBlock)
	return certPEM, keyPEM
}

func NewServerTLSConfig(cert tls.Certificate) (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}, nil
}

func NewClientTLSConfig(caPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
}
