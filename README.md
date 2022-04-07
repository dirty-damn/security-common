
# 基于JCA安全体系的封装

所有涵盖的安全算法均在JCA体系结构下，所有算法均由JEC提供，目的是提供方便快捷的使用方式。

目前主要功能包括：
- 摘要算法
- RSA密钥
- 签名算法
- AES算法
- RSA算法

## 1 背景
项目依赖除了JDK1.8自带的JCE外，还依赖了bouncycastle提供的JCE。

本项目需要在JDK1.8_8u161及之后的版本使用，否则需要自行解除限制。

>在JDK1.8_8u161之前的版本，由于出口政策限制，AES密钥只能到128位，使用密钥大于128位将出现报错信息，请参考Oracle官方说明：
[https://www.oracle.com/java/technologies/javase-jce-all-downloads.html](https://www.oracle.com/java/technologies/javase-jce-all-downloads.html)

## 2 使用方式

在test目录下覆盖了所有算法及密钥的测试例子，并且已经测试通过，这里仅做常用演示。

### 2.1 摘要算法

```java
String digest1 = Digest.use(DigestEnum.SHA256).digest("123");
```
使用use()指定摘要算法进行计算，结果以Hex十六进行结果输出。方法是线程安全的。
DigestEnum包含了包括openssl 1.1.1m能提供的所有摘要算法，除了mdc2。
```
Message Digest commands (see the `dgst' command for more details)
blake2b512        blake2s256        gost              md4
md5               --mdc2            rmd160            sha1
sha224            sha256            sha3-224          sha3-256
sha3-384          sha3-512          sha384            sha512
sha512-224        sha512-256        shake128          shake256
sm3
```

### 2.2 RSA密钥

长度包括1024和2048。

包含如下功能：
1. 生成RSA密钥对
2. 字节数组转为公钥/私钥
3. 公钥/私钥的PKCS1和PKCS8互转.
4. 读取PEM格式的公钥/私钥
5. 公钥/私钥生成PKCS1和PKCS8的PEM格式字符串

以下举例：

生成RSA密钥对
```java
RSAKeyPair rsaKeyPair = RSAKeyPair.generator(RSAKeyEnum.KEY_1024);
```

获取PKCS8格式的PEM
```java
String pkcs8 = rsaKeyPair.getRsaPvtKey().getPemPKCS8();
```

读取PKCS1格式公钥，并转为PKCS8的字节数组
```java
String pemPKCS1Pub = "-----BEGIN RSA PUBLIC KEY-----\r\n" +
                "MIGJAoGBAId7rfXopAhYF6EeUkGIUP426+inmWFYLS7lsvgQezmC0CduaQcy4QrR\r\n" +
                "TGi6m/hB0uY6/g0nv2qpq2SQLSpro8EKtG98kxroTsgIeEfEfPpr1cR1FUq4wmbF\r\n" +
                "H2XliwXEXwgtPLp39MMTHQbYVPs36wqIQkxukSBdqt7AHOkw2VdTAgMBAAE=\r\n" +
                "-----END RSA PUBLIC KEY-----" +
                "\r\n";
RSAPubRSAKey rsaPubKey1 = RSAPubRSAKey.instanceFromPem(pemPKCS1Pub);
byte[] bytesPKCS8 = rsaPubKey1.getBytesPKCS8();
```

### 2.3 签名算法

签名算法使用到RSA密钥，私钥签名，公钥验签。

```java
RSAPvtRSAKey rsaPvtKey = RSAPvtRSAKey.instanceFromPem(pemPKCS8);
String sign = Sign.sign(SignatureEnum.SHA1WithRSA, "123", rsaPvtKey.getPrivateKey());

RSAPubRSAKey rsaPubKey = RSAPubRSAKey.instanceFromPem(pemPKCS8Pub);
boolean verify = Sign.verify(SignatureEnum.SHA1WithRSA, "123", sign, rsaPubKey.getPublicKey());

Assert.assertTrue(verify);
```

可支持的签名算法在SignatureEnum枚举类型中，如下:
```java
// SHA1
SHA1WithRSA("SHA1WithRSA"),
// SHA2
SHA224WITHRSA("SHA224WITHRSA"),
SHA256WITHRSA("SHA256WITHRSA"),
SHA384WITHRSA("SHA384WITHRSA"),
SHA512WITHRSA("SHA512WITHRSA"),
// SHA3
SHA3_224WITHRSA("SHA3-224WITHRSA"),
SHA3_384WITHRSA("SHA3-384WITHRSA"),
SHA3_256WITHRSA("SHA3-256WITHRSA"),
SHA3_512WITHRSA("SHA3-512WITHRSA"),
// MD5
MD5WITHRSA("MD5WITHRSA"),
// MD5 SHA1
MD5ANDSHA1WITHRSA("MD5ANDSHA1WITHRSA"),
// RMD
RMD128WITHRSA("RMD128WITHRSA"),
RMD160WITHRSA("RMD160WITHRSA"),
RMD256WITHRSA("RMD256WITHRSA"),
```

### 2.4 







