package top.senseiliu.security.key.rsa;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.pem.PemObject;
import top.senseiliu.security.key.KeyConstant;

/**
 * RSA私钥对象，继承RSAKey
 *
 * @author liuguanliang
 */
public class RSAPvtRSAKey extends RSAKey {

    public RSAPvtRSAKey(byte[] rsaPvtKey) {
        super(rsaPvtKey);
    }

    /**
     * 获取PEM格式的PKCS1的私钥
     *
     * @return 返回PKCS8格式的PEM
     */
    @Override
    public byte[] getBytesPKCS1() {
        return PKCS8ToPKCS1(this.keyBytes);
    }

    /**
     * PKCS8格式的PEM密钥头信息
     *
     * @return 返回PKCS8格式的PEM头信息
     */
    @Override
    protected String pemPKCS8Header() {
        return KeyConstant.PVT_PKCS8;
    }

    /**
     * PKCS1格式的PEM密钥头信息
     *
     * @return 返回PKCS1格式的PEM头信息
     */
    @Override
    protected String pemPKCS1Header() {
        return KeyConstant.PVT_PKCS1;
    }

    /**
     * RSA私钥PKCS1转PKCS8
     *
     * @param keyBytes PKCS1公钥字节数组
     * @return PKCS8公钥字节数组
     */
    public static byte[] PKCS1ToPKCS8(byte[] keyBytes) {
        byte[] pkcs8Bytes = null;

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag);
        try {
            ASN1Object asn1Object = ASN1ObjectIdentifier.fromByteArray(keyBytes);
            PrivateKeyInfo privKeyInfo = new PrivateKeyInfo(algorithmIdentifier, asn1Object);
            pkcs8Bytes = privKeyInfo.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("[KeyFactory]转PKCS8私钥时发生异常，msg：{}" + e.getMessage());
        }

        return pkcs8Bytes;
    }

    /**
     * RSA私钥PKCS8转PKCS1
     *
     * @param keyBytes PKCS8公钥字节数组
     * @return PKCS1公钥字节数组
     */
    public static byte[] PKCS8ToPKCS1(byte[] keyBytes) {
        byte[] privateKeyPKCS1 = null;

        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(keyBytes);
        try {
            ASN1Encodable encodable = pkInfo.parsePrivateKey();
            ASN1Primitive primitive = encodable.toASN1Primitive();
            privateKeyPKCS1 = primitive.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("[PrivateKeyInfo]私钥转PKCS1时发生异常，msg：{}" + e.getMessage());
        }

        return privateKeyPKCS1;
    }

    /**
     * 通过PEM字符串实例化RSA私钥对象
     *
     * @param pem PEM格式字符串
     * @return RSA私钥对象
     */
    public static RSAPvtRSAKey instanceFromPem(String pem) {
        PemObject pemObject = readPem(pem);

        String type = pemObject.getType();
        if (!KeyConstant.PVT_PKCS8.equals(type) && !KeyConstant.PVT_PKCS1.equals(type)) {
            throw new RuntimeException("[PemObject]仅支持RSA的PKCS1和PKCS8类型的私钥格式");
        }

        byte[] content = pemObject.getContent();
        if (KeyConstant.PVT_PKCS1.equals(type)) {
            content = RSAPvtRSAKey.PKCS1ToPKCS8(content);
        }

        return new RSAPvtRSAKey(content);
    }
}