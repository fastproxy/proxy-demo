#!/bin/bash
set -ex

mkdir root

# 创建 Root Key
openssl ecparam -out root/ca.key.pem -name prime256v1 -genkey -noout

curl -o ./root/openssl.cnf https://gist.githubusercontent.com/foreverzmy/0b07d3a731d70519e35ced070118e3fe/raw/71210c2643b8997ea6e2cf333e26aa33e712a7e2/simple-root-ca.cnf

# 创建 Root Cert
openssl req -config root/openssl.cnf \
      -key root/ca.key.pem \
      -passin pass:123456 \
      -new \
      -x509 \
      -days 7300 \
      -sha256 \
      -extensions v3_ca \
      -out root/ca.cert.pem \
      -subj /C=CN/ST=Shanghai/L=Shanghai/O=JediLtd/OU=JediProxy/CN=JediRootCA/emailAddress=921255465@qq.com

chmod 400 root/ca.cert.pem

# 验证证书
# openssl x509 -noout -text -in root/ca.cert.pem

# 创建 Intermediate Pair

# 创建 intermediate 文件夹存放 Intermediate Pair
mkdir intermediate

# 创建 Intermediate Key
openssl ecparam -out intermediate/intermediate.key.pem -name prime256v1 -genkey -noout

chmod 400 intermediate/intermediate.key.pem

curl -o ./intermediate/openssl.cnf https://gist.githubusercontent.com/foreverzmy/936b1bb55adf52c5d1accc9b2216a0e3/raw/28b9f97df967d93febf09219863190aea3b36895/simple-intermediate-ca-cnf

# 创建 Intermediate Cert
openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/intermediate.key.pem \
      -passin pass:123456 \
      -out intermediate/intermediate.csr.pem \
      -subj /C=CN/ST=Shanghai/L=Shanghai/O=JediLtd/OU=JediProxy/CN=JediIntermediateCA/emailAddress=921255465@qq.com

chmod 400 intermediate/intermediate.key.pem

touch root/index.txt
echo 1000 > root/serial
# 使用 v3_intermediate_ca 扩展签名，密码为 123456
# Intermediate Pair 的有效时间一定要为 Root Pair 的子集
openssl ca -config root/openssl.cnf \
      -extensions v3_intermediate_ca \
      -days 3650 \
      -notext \
      -md sha256 \
      -passin pass:123456 \
      -in intermediate/intermediate.csr.pem \
      -out intermediate/intermediate.cert.pem

chmod 444 intermediate/intermediate.cert.pem

# 验证 Intermediate Pair
# openssl x509 -noout -text -in intermediate/intermediate.cert.pem
# openssl verify -CAfile root/ca.cert.pem intermediate/intermediate.cert.pem

# 浏览器在验证中间证书的时候，同时也会去验证它的上一级证书是否靠谱
# 创建证书链，将 Root Cert 和 Intermediate Cert 合并到一起，可以让浏览器一并验证
cat intermediate/intermediate.cert.pem root/ca.cert.pem > intermediate/ca-chain.cert.pem
chmod 444 intermediate/ca-chain.cert.pem

# 创建服务器/客户端证书

# 创建 foreverz.cn 存放域名相关证书文件
mkdir foreverz.cn

# 生成域名私钥
openssl ecparam -out foreverz.cn/foreverz.cn.key.pem -name prime256v1 -genkey -noout

# 创建网站证书请求
openssl req -config intermediate/openssl.cnf \
      -key foreverz.cn/foreverz.cn.key.pem \
      -new -sha256 \
      -out foreverz.cn/foreverz.cn.req \
      -subj /C=CN/ST=Shanghai/L=Shanghai/O=JediLtd/OU=JediProxy/CN=foreverz.cn/emailAddress=921255465@qq.com

# 签发网站证书
openssl x509 -req -in foreverz.cn/foreverz.cn.req \
      -days 375 \
      -sha256 \
      -CA intermediate/intermediate.cert.pem \
      -CAkey intermediate/intermediate.key.pem \
      -CAcreateserial \
      -out foreverz.cn/foreverz.cn.cert.pem

# 验证证书
# openssl x509 -noout -text -in foreverz.cn/foreverz.cn.cert.pem
openssl verify -CAfile intermediate/ca-chain.cert.pem foreverz.cn/foreverz.cn.cert.pem

# https://ss64.com/osx/security.html
# sudo security add-trusted-cert -d -r trustRoot -k $(echo `security default-keychain`) ./intermediate/ca-chain.cert.pem
# security verify-cert -c ./root/ca.cert.pem
# sudo security remove-trusted-cert -d intermediate/intermediate.cert.pem
# $security default-keychain
