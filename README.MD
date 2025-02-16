
## 初始化hsm
softhsm2-util --init-token --slot 0 --label "MyToken" --pin 12345678 --so-pin 88888888

## 列举token
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --list-tokens

## 导入密钥对
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key private.key -out cert.pem -days 365
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --login --write --load-privkey private.key --label "MyKey"

## List all available objects in a token
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --login --list-all

## 列举所有私钥
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --login --list-all-privkeys

## 生成密钥对
p11tool --provider /usr/lib64/pkcs11/libsofthsm2.so --login --generate-rsa --bits 2048 --label "MyKey"

## openssl生成csr
openssl req -engine pkcs11 -key "pkcs11:token=MyToken;object=MyKey;type=private" -keyform engine -new -out new_device.csr -subj "/CN=NEW CSR EXAMPLE"

## openssl生成crt
openssl x509 -req -engine pkcs11 -key "pkcs11:token=MyToken;object=MyKey;type=private" -keyform engine -in new_device.csr -days 365 -out new_device.crt

## openssl检查csr crt文件信息
openssl req -engine pkcs11 -in new_device.csr -text -noout 
openssl x509 -engine pkcs11 -in cert.crt -text -noout

## 一个命令生成私钥和crt
openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out cert.crt -days 365 -nodes \
-subj "/C=CN/ST=Beijing/L=Beijing/O=Example Company/OU=IT Department/CN=example.com"