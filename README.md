# Proxy Demo

用Go实现的HTTP(S)代理&抓包工具Demo。

## 运行步骤

### 1. 生成CA证书

```shell
go test -v -run TestGenerateRootPair .
go test -v -run TestGenerateInterPair .
```

### 安装CA证书

Mac 用户可以使用以下命令安装证书：

```shell
keychain=`security login-keychain | awk '$1=$1'`
eval $(echo "security add-trusted-cert -d -r trustRoot -p ssl -k $keychain ./cert/ca.cert.pem")
eval $(echo "security add-trusted-cert -d -r trustRoot -p ssl -k $keychain ./cert/inter.cert.pem")
```

### 启动项目

```shell
go run .
```

### 设置为系统代理

```shell
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 6789 & networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 6789
```

### 确认代理成功

打开浏览器，访问任意网站，看到 Response Header 有 `X-Proxy-Server: Jedi/0.1` 代表代理成功。

### 取消代理

```shell
networksetup -setwebproxystate "Wi-Fi" off & networksetup -setsecurewebproxystate "Wi-Fi" off
```

### 删除证书

```shell
security remove-trusted-cert -d ./cert/inter.cert.pem
eval $(echo "security delete-certificate -c 'Jedi Inter CA' $keychain")
security remove-trusted-cert -d ./cert/ca.cert.pem
eval $(echo "security delete-certificate -c 'Jedi Root CA' $keychain")
```

### 关闭程序

Done.
