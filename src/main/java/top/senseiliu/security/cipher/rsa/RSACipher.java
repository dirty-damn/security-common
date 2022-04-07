package top.senseiliu.security.cipher.rsa;

import javax.crypto.Cipher;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import top.senseiliu.security.cipher.AbstractCipher;
import top.senseiliu.security.cipher.Constant;

/**
 * RSA加密算法只有ECB模式没有其他模式
 * 参考：http://cn.voidcc.com/question/p-cadbjyyt-uq.html
 *
 * @author liuguanliang
 */
public class RSACipher extends AbstractCipher {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private String algorithm;

    /**
     * 只能通过{@link #init() init()}方法初始化
     */
    private RSACipher() {}

    /**
     * 有子类提供具体的算法名称，模板方法
     *
     * @return 算法名称
     */
    @Override
    protected String algorithm() {
        return algorithm;
    }

    /**
     * 实现加密算法和密钥的初始化
     *
     * @param cipher 算法对象
     * @param key 对称密钥/公钥
     */
    @Override
    protected void initCipherEncrypt(Cipher cipher, Key key) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
        }
    }

    /**
     * 实现解密算法和密钥的初始化
     *
     * @param cipher 算法对象
     * @param key 对称密钥/私钥
     */
    @Override
    protected void initCipherDecrypt(Cipher cipher, Key key) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("[Cipher]解密密钥异常，msg：" + e.getMessage());
        }
    }

    private void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * 静态方法获取RSACipher实例
     * 不带参数默认使用PKCS1填充，RSA只有ECB模式
     *
     * @return RSACipher实例
     */
    public static RSACipher init() {
        String algorithm = Constant.RSA + Constant.DELIMITER + "ECB" + Constant.DELIMITER + RSAPaddingModeEnum.PKCS1.getDesc();

        RSACipher rsaCipher = new RSACipher();
        rsaCipher.setAlgorithm(algorithm);
        return rsaCipher;
    }

    /**
     * 静态方法获取RSACipher实例
     * 指定RSA填充方式
     *
     * @param rsaPaddingModeEnum RSA填充模式枚举
     * @return RSACipher实例
     */
    public static RSACipher init(RSAPaddingModeEnum rsaPaddingModeEnum) {
        String algorithm = Constant.RSA + Constant.DELIMITER + "ECB" + Constant.DELIMITER + rsaPaddingModeEnum.getDesc();

        RSACipher rsaCipher = new RSACipher();
        rsaCipher.setAlgorithm(algorithm);
        return rsaCipher;
    }
}
