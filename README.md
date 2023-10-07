
# Win7 Handshake
A tool to verify that your SSL configuration is compatible with win7's schannel.

# Usage

```bash
$ go run win7_handshake.go -verbose -hosts baidu.com:443,google.com
2023/05/19 11:50:24 host:baidu.com:443, handshake successfully with cipher suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
2023/05/19 11:50:25 host:google.com:443, handshake successfully with cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
```

# Known Issues
These cipher suites are supported by win7's schannel, but not supported by Go, so the test result will be false-postive.

	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	TLS_RSA_WITH_AES_256_CBC_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	TLS_RSA_WITH_RC4_128_MD5

# Reference
1. [TLS Cipher Suites in Windows 7](https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-7)