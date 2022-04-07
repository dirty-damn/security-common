package top.senseiliu.security.key.rsa;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import top.senseiliu.security.key.KeyConstant;

/**
 * RSA公钥对象，继承RSAKey
 *
 * @author liuguanliang
 */
public class RSAPubRSAKey extends RSAKey {

    public RSAPubRSAKey(byte[] rsaPubKey) {
        super(rsaPubKey);
    }

    /**
     * 获取PublicKey
     *
     * @return PublicKey
     */
    public PublicKey getPublicKey() {
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(KeyConstant.RSA);
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[KeyFactory]getInstance()时找不到{0}的KeyFactory提供者，msg：{1}", KeyConstant.RSA, e.getMessage()));
        }

        PublicKey publicKey = null;
        try {
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(this.keyBytes));
        } catch (Exception e) {
            throw new RuntimeException("[keyFactory]bytes转PrivateKey时发生异常，msg：{0}" + e.getMessage());
        }

        return publicKey;
    }

    /**
     * 获取PEM格式的PKCS1的公钥
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
        return KeyConstant.PUB_PKCS8;
    }

    /**
     * PKCS1格式的PEM密钥头信息
     *
     * @return 返回PKCS1格式的PEM头信息
     */
    @Override
    protected String pemPKCS1Header() {
        return KeyConstant.PUB_PKCS1;
    }

    /**
     * RSA公钥PKCS1转PKCS8
     *
     * @param keyBytes PKCS1公钥字节数组
     * @return PKCS8公钥字节数组
     */
    public static byte[] PKCS1ToPKCS8(byte[] keyBytes) {
        KeyFactory keyFactory = null;

        RSAPublicKey rsaPub = RSAPublicKey.getInstance(keyBytes);
        try {
            keyFactory = KeyFactory.getInstance(KeyConstant.RSA);
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[KeyFactory]getInstance()时找不到{0}的KeyFactory提供者，msg：{1}", KeyConstant.RSA, e.getMessage()));
        }

        PublicKey publicKey = null;
        try {
            publicKey =  keyFactory.generatePublic(new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent()));
        } catch (Exception e) {
            throw new RuntimeException("[ASN1InputStream]公钥转PKCS8时发生异常，msg：{0}" + e.getMessage());
        }

        return publicKey.getEncoded();
    }

    /**
     * RSA公钥PKCS8转PKCS1
     *
     * @param keyBytes PKCS8公钥字节数组
     * @return PKCS1公钥字节数组
     */
    public static byte[] PKCS8ToPKCS1(byte[] keyBytes) {
        byte[] encoded = null;

        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(keyBytes);
        try {
            ASN1Primitive primitive = spkInfo.parsePublicKey();
            encoded = primitive.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("[SubjectPublicKeyInfo]公钥转PKCS1时发生异常，msg：{0}" + e.getMessage());
        }

        return encoded;
    }

    /**
     * 通过PEM字符串实例化RSA公钥对象
     *
     * @param pem PEM格式字符串
     * @return RSA公钥对象
     */
    public static RSAPubRSAKey instanceFromPem(String pem) {
        PemObject pemObject = readPem(pem);

        String type = pemObject.getType();
        if (!KeyConstant.PUB_PKCS8.equals(type) && !KeyConstant.PUB_PKCS1.equals(type)) {
            throw new RuntimeException("[PemObject]仅支持RSA的PKCS1和PKCS8类型的公钥格式");
        }

        byte[] content = pemObject.getContent();
        if (KeyConstant.PUB_PKCS1.equals(type)) {
            content = RSAPubRSAKey.PKCS1ToPKCS8(content);
        }

        return new RSAPubRSAKey(content);
    }
}