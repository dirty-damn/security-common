
# 基于JCA安全体系的封装

所有涵盖的安全算法均在JCA体系结构下，所有算法均由JEC提供，目的是提供方便快捷的使用方式。

目前主要功能包括：
- 摘要算法
- RSA密钥
- 签名算法
- RSA算法
- AES算法

## 1 背景
项目依赖除了JDK1.8自带的JCE外，还依赖了**bouncycastle**提供的JCE。

本项目需要在**JDK1.8_8u161**及之后的版本使用，否则需要自行解除限制。

>在JDK1.8_8u161之前的版本，由于出口政策限制，AES密钥只能到128位，使用密钥大于128位将出现报错信息，请参考Oracle官方说明：
[https://www.oracle.com/java/technologies/javase-jce-all-downloads.html](https://www.oracle.com/java/technologies/javase-jce-all-downloads.html)

## 2 依赖



## 3 使用实例

在test目录下覆盖了所有算法及密钥的测试例子，并且已经测试通过，这里仅做常用演示。

### 3.1 摘要算法

```java
String digest1 = Digest.use(DigestEnum.SHA256).digest("123");
```
使用use()指定摘要算法进行计算，结果以Hex十六进行结果输出。方法是线程安全的。
**DigestEnum**包含了包括openssl 1.1.1m能提供的所有摘要算法，除了mdc2，openssl命令工具如下：
```
Message Digest commands (see the `dgst' command for more details)
blake2b512        blake2s256        gost              md4
md5               --mdc2            rmd160            sha1
sha224            sha256            sha3-224          sha3-256
sha3-384          sha3-512          sha384            sha512
sha512-224        sha512-256        shake128          shake256
sm3
```

**DigestEnum**支持如下：

```java
BLAKE2B512("BLAKE2B-512"),
BLAKE2S512("BLAKE2S-256"),
GOST("GOST3411"),
MD4("MD4"),
MD5("MD5"),
RMD128("RIPEMD128"),
RMD160("RIPEMD160"),
RMD256("RIPEMD256"),
// SHA1
SHA1("SHA-1"),
// SHA2，SHA-224、SHA-256、SHA-384，和SHA-512并称为SHA2
SHA224("SHA-224"),
SHA256("SHA-256"),
SHA384("SHA-384"),
SHA512("SHA-512"),
// SHA3，SHA3-224、SHA3-256、SHA3-384，和SHA3-512并称为SHA3
SHA3_224("SHA3-224"),
SHA3_256("SHA3-256"),
SHA3_384("SHA3-384"),
SHA3_512("SHA3-512"),
// SHA512
SHA512_256("SHA-512/256"),
SHA512_224("SHA-512/224"),
// SHAKE
SHAKE128("SHAKE128-256"),
SHAKE256("SHAKE256-512"),
// 国密hash
SM3("SM3"),
```

### 3.2 RSA密钥

长度包括1024和2048。

包含如下功能：
1. 生成RSA密钥对
2. 字节数组转为公钥/私钥
3. 公钥/私钥的PKCS1和PKCS8互转.
4. 读取PEM格式的公钥/私钥
5. 公钥/私钥生成PKCS1和PKCS8的PEM格式字符串
6. 证书提取PKCS8的公钥

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

### 3.3 签名算法

签名算法使用到RSA密钥，私钥签名，公钥验签。

```java
RSAPvtRSAKey rsaPvtKey = RSAPvtRSAKey.instanceFromPem(pemPKCS8);
String sign = Sign.sign(SignatureEnum.SHA1WithRSA, "123", rsaPvtKey.getPrivateKey());

RSAPubRSAKey rsaPubKey = RSAPubRSAKey.instanceFromPem(pemPKCS8Pub);
boolean verify = Sign.verify(SignatureEnum.SHA1WithRSA, "123", sign, rsaPubKey.getPublicKey());

Assert.assertTrue(verify);
```

可支持的签名算法在**SignatureEnum**枚举类型中，如下:
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

### 3.4 算法

加密过程共由这些内容组成，**密码算法、密钥、密钥填充、加密模式、明文填充、VI初始偏移量和编解码器。**

不同算法或不同模式所需要的内容不同，这里不对密码算法理论作过多介绍，在具体算法章节作说明。

#### 3.4.1 AES

AES密钥长度包括128、192以及256位。**AESKeyEnum**如下：
```java
KEY_128(128, 16),
KEY_192(192, 24),
KEY_256(256, 32),
```

> 在JDK1.8_8u161之前的版本，由于出口政策限制，AES密钥只能到128位，使用密钥大于128位将出现报错信息，解除限制参考：
>[https://www.oracle.com/java/technologies/javase-jce-all-downloads.html](https://www.oracle.com/java/technologies/javase-jce-all-downloads.html)

加密模式枚举**EncryptModeEnum**如下：
```java
// ECB-电码本模式 CBC-密文分组链接方式 CFB-密文反馈模式 OFB-输出反馈模式
ECB("ECB"),
CBC("CBC"),
CFB("CFB"),
OFB("OFB"),
```
> 除ECB模式外，**其他模式**都需要IV初始限量，IV是一个16字节长度的偏移量，可自定或生成。

填充模式枚举**PaddingModeEnum**如下：
```java
NoPadding("NoPadding"),
PKCS5("PKCS5Padding"),
ISO10126("ISO10126Padding "),
```

使用说明

默认为256/ECB/PKCS5算法，使用Base64编解码
```java
AESCipher aesCipher = AESCipher.init();
String encrypt = aesCipher.encrypt("123", aesCipher.getKey("123".getBytes()));
String decrypt = aesCipher.decrypt(encrypt, aesCipher.getKey("123".getBytes()));
Assert.assertEquals(decrypt, "123");
```

指定算法参数，指定Hex十六进制编解码器
```java
AESParam aesParam = new AESParam(AESKeyEnum.KEY_128, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, "1234567890123456");
AESCipher aesCipher1 = AESCipher.init(aesParam);
String encrypt1 = aesCipher1.encrypt("123", aesCipher1.getKey("123".getBytes()), AbstractCipher.encPostHexHandler);
String decrypt1 = aesCipher1.decrypt(encrypt1, aesCipher1.getKey("123".getBytes()), AbstractCipher.decPreHexHandler);
Assert.assertEquals(decrypt1, "123");
```

#### 3.4.2 RSA

与AES不同，RSA算法只有ECB模式，JEC没有提供RSA的其他加密模式。
填充模式枚举**RSAPaddingModeEnum**如下：
```java
NoPadding("NoPadding"),
PKCS1("PKCS1Padding"),
OAEP("OAEPPadding"),
```

> OAEP是PKCS1的v2版，可以看作是升级版本。

```java
RSACipher rsaCipher = RSACipher.init();
String encrypt = rsaCipher.encrypt("123", rsaPubKey.getPublicKey());
String decrypt = rsaCipher.decrypt(encrypt, rsaPvtKey.getPrivateKey());
Assert.assertEquals(decrypt, "123");

RSACipher rsaCipher1 = RSACipher.init(RSAPaddingModeEnum.OAEP);
// 指定编解码器
String encrypt1 = rsaCipher1.encrypt("123", rsaPubKey.getPublicKey(), AbstractCipher.encPostHexHandler);
String decrypt1 = rsaCipher1.decrypt(encrypt1, rsaPvtKey.getPrivateKey(), AbstractCipher.decPreHexHandler);
Assert.assertEquals(decrypt1, "123");
```