package top.senseiliu.security.key;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.MessageFormat;

/**
 * RSA公私钥工具类
 *
 * @author liuguanliang
 */
public final class RSAKey {


    private RSAKey() {}

    /**
     * 生成指定长度的RSA公私钥
     *
     * @param rsaKeyEnum RSA密钥长度枚举
     */
    public static KeyPair keyPairGenerator(RSAKeyEnum rsaKeyEnum) {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KeyConstant.RSA);
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[KeyPairGenerator]getInstance()时找不到{}的KeyPairGenerator提供者，msg：{}", KeyConstant.RSA, e.getMessage()));
        }
        keyPairGenerator.initialize(rsaKeyEnum.getKeyLength());
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new KeyPair(new KeyPair.RSAPubKey(rsaPublicKey.getEncoded()), new KeyPair.RSAPvtKey(rsaPrivateKey.getEncoded()));
    }

}
