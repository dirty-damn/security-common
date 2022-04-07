package top.senseiliu.security.key.rsa;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;

import top.senseiliu.security.key.KeyConstant;

/**
 * RSA密钥对
 * 包含一个生成密钥对的静态方法
 *
 * @author liuguanliang
 */
public class RSAKeyPair {
    private RSAPubRSAKey rsaPubKey;
    private RSAPvtRSAKey rsaPvtKey;

    public RSAKeyPair() {}

    public RSAKeyPair(RSAPubRSAKey rsaPubKey, RSAPvtRSAKey rsaPvtKey) {
        this.rsaPubKey = rsaPubKey;
        this.rsaPvtKey = rsaPvtKey;
    }

    /**
     * 生成指定长度的RSA公私钥
     *
     * @param rsaKeyEnum RSA密钥长度枚举
     * @return RSA密钥对对象
     */
    public static RSAKeyPair generator(RSAKeyEnum rsaKeyEnum) {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KeyConstant.RSA);
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[KeyPairGenerator]getInstance()时找不到{0}的KeyPairGenerator提供者，msg：{1}", KeyConstant.RSA, e.getMessage()));
        }
        keyPairGenerator.initialize(rsaKeyEnum.getKeyLength());
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKeyPair(new RSAPubRSAKey(rsaPublicKey.getEncoded()), new RSAPvtRSAKey(rsaPrivateKey.getEncoded()));
    }

    public RSAPubRSAKey getRsaPubKey() {
        return rsaPubKey;
    }

    public void setRsaPubKey(RSAPubRSAKey rsaPubKey) {
        this.rsaPubKey = rsaPubKey;
    }

    public RSAPvtRSAKey getRsaPvtKey() {
        return rsaPvtKey;
    }

    public void setRsaPvtKey(RSAPvtRSAKey rsaPvtKey) {
        this.rsaPvtKey = rsaPvtKey;
    }
}
