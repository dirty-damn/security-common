package top.senseiliu.security.key;

import java.io.StringReader;
import java.io.StringWriter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class AbstractKey {
    // 存放PKCS8的字节数据
    private final byte[] keyBytes;
    // 是否公钥
    private final Boolean isPub;

    public AbstractKey(byte[] keyBytes, Boolean isPub) {
        this.keyBytes = keyBytes;
        this.isPub = isPub;
    }

    public byte[] getPKCS8Bytes() {
        return keyBytes;
    }

    /**
     * 获取PEM格式的PKCS8的公私钥
     */
    public String getPKCS8() {
        return isPub ? getPKCS8Pub() : getPKCS8Pvt();
    }

    /**
     * 获取PEM格式的PKCS1的公私钥
     */
    public String getPKCS1() {
        return isPub ? getPKCS1Pub() : getPKCS1Pvt();
    }

    private String getPKCS8Pvt() {
        return getPem(KeyConstant.PVT_PKCS8, keyBytes);
    }

    private String getPKCS8Pub() {
        return getPem(KeyConstant.PUB_PKCS8, keyBytes);
    }

    private String getPKCS1Pvt() {
        byte[] privateKeyPKCS1 = null;

        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(keyBytes);
        try {
            ASN1Encodable encodable = pkInfo.parsePrivateKey();
            ASN1Primitive primitive = encodable.toASN1Primitive();
            privateKeyPKCS1 = primitive.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("[PrivateKeyInfo]私钥转PKCS1时发生异常，msg：{}" + e.getMessage());
        }

        return getPem(KeyConstant.PVT_PKCS1, privateKeyPKCS1);
    }

    public byte[] getPKCS1PubBytes() {
        byte[] encoded = null;

        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(keyBytes);
        try {
            ASN1Primitive primitive = spkInfo.parsePublicKey();
            encoded = primitive.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("[SubjectPublicKeyInfo]公钥转PKCS1时发生异常，msg：{}" + e.getMessage());
        }

        return encoded;
    }

    private String getPKCS1Pub() {
        byte[] pkcs1PubBytes = getPKCS1PubBytes();
        return getPem(KeyConstant.PUB_PKCS1, pkcs1PubBytes);
    }

    private String getPem(String header, byte[] bytes) {
        PemObject pemObject = new PemObject(header, bytes);
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(pemObject);
        } catch (Exception e) {
            throw new RuntimeException("[PemWriter]写PEM时发生异常，msg：{}" + e.getMessage());
        }

        return stringWriter.toString();
    }

    /**
     * 读取PEM格式的字符串
     *
     * @param pem pem的密钥
     * @return PemObject Pem对象
     */
    public static PemObject getPemObject(String pem) {
        if (null == pem || pem.isEmpty()) {
            throw new RuntimeException("[PemObject]参数pem不能为空");
        }

        StringReader stringReader = new StringReader(pem);
        PemReader pemReader = new PemReader(stringReader);
        PemObject pemObject = null;
        try {
            pemObject = pemReader.readPemObject();
        } catch (Exception e) {
            throw new RuntimeException("[PemObject]读取pem时发生了异常，msg：{}" + e.getMessage());
        }
        return pemObject;
    }

}
