#!/bin/bash
set -ex

# 创建 Root Pair

# 创建 root 文件夹存放 Root Pair
mkdir root

# 创建 Root Key
openssl genrsa -aes256 -passout pass:123456 -out root/ca.key.pem 4096

chmod 400 root/ca.key.pem

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
openssl genrsa -aes256 -passout pass:123456 -out intermediate/intermediate.key.pem 4096

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

# Root pair 和 intermediate pair 使用的都是 4096 位的加密方式
# 一般情况下服务器/客户端证书的过期时间为一年，所以可以安全地使用 2048 位的加密方式
openssl genrsa -aes256 -passout pass:123456 -out foreverz.cn/foreverz.cn.key.pem 2048

# 创建网站证书
openssl req -config intermediate/openssl.cnf \
      -key foreverz.cn/foreverz.cn.key.pem \
      -passin pass:123456 \
      -new -sha256 \
      -out foreverz.cn/foreverz.cn.csr.pem \
      -subj /C=CN/ST=Shanghai/L=Shanghai/O=JediLtd/OU=JediProxy/CN=foreverz.cn/emailAddress=921255465@qq.com


touch intermediate/index.txt
echo 1000 > intermediate/serial

# 使用 intermediate pair 签证网站证书
openssl ca -config intermediate/openssl.cnf \
      -extensions server_cert \
      -days 375 \
      -notext \
      -md sha256 \
      -in foreverz.cn/foreverz.cn.csr.pem \
      -passin pass:123456 \
      -out foreverz.cn/foreverz.cn.cert.pem

# 验证证书
# openssl x509 -noout -text -in foreverz.cn/foreverz.cn.cert.pem
openssl verify -CAfile intermediate/ca-chain.cert.pem foreverz.cn/foreverz.cn.cert.pem

# CA 根证书：ca-chain.cert.pem
# 网站私钥：foreverz.cn.key.pem
# 网站公钥：foreverz.cn.cert.pem
