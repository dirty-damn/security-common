package top.senseiliu.security.cipher.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import top.senseiliu.security.cipher.AbstractCipher;
import top.senseiliu.security.cipher.Constant;
import top.senseiliu.security.cipher.aes.constant.AESKeyEnum;
import top.senseiliu.security.cipher.aes.constant.EncryptModeEnum;
import top.senseiliu.security.cipher.aes.constant.PaddingModeEnum;

/**
 * AES加解密算法，提供了加密和加密的静态方法
 * 密钥截取的方法，大于选定长度截断，小于则用'\0'填充，即用0X00填充字节
 *
 * 关于密钥长度的限制，如下：
 * JDK 9 and later offer the stronger cryptographic algorithms by default.
 *
 * The unlimited policy files are required only for JDK 8, 7, and 6 updates earlier than 8u161, 7u171, and 6u181.
 * On those versions and later, the stronger cryptographic algorithms are available by default.
 * 参考：https://www.oracle.com/java/technologies/javase-jce-all-downloads.html
 *
 * @author liuguanliang
 */
public class AESCipher extends AbstractCipher {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private AESParam aesParam;

    /**
     * 只能通过{@link #init()}方法初始化
     */
    private AESCipher() {}

    /**
     * 有子类提供具体的算法名称，模板方法
     *
     * @return 算法名称
     */
    @Override
    protected String algorithm() {
        return Constant.AES + Constant.DELIMITER + this.aesParam.getEncryptModeEnum().getDesc() + Constant.DELIMITER + aesParam.getPaddingModeEnum().getDesc();
    }

    /**
     * 实现加密算法和密钥的初始化
     *
     * @param cipher 算法对象
     * @param key 对称密钥/公钥
     */
    @Override
    protected void initCipherEncrypt(Cipher cipher, Key key) {
        if (EncryptModeEnum.ECB.equals(aesParam.getEncryptModeEnum())) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } catch (InvalidKeyException e) {
                throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
            }
        } else {
            if ((null == aesParam.getIv() || aesParam.getIv().isEmpty())) {
                throw new RuntimeException("[Cipher]除ECB模式外，其他模式都需要IV初始偏移量");
            }

            IvParameterSpec iv = new IvParameterSpec(aesParam.getIv().getBytes());
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            } catch (Exception e) {
                throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
            }
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
        if (EncryptModeEnum.ECB.equals(aesParam.getEncryptModeEnum())) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, key);
            } catch (InvalidKeyException e) {
                throw new RuntimeException("[Cipher]解密密钥异常，msg：" + e.getMessage());
            }
        } else {
            if ((null == aesParam.getIv() || aesParam.getIv().isEmpty())) {
                throw new RuntimeException("[Cipher]除ECB模式外，其他模式都需要IV初始偏移量");
            }

            IvParameterSpec iv = new IvParameterSpec(aesParam.getIv().getBytes());
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
            } catch (Exception e) {
                throw new RuntimeException("[Cipher]解密密钥异常，msg：" + e.getMessage());
            }
        }
    }

    /**
     * 填充key，根据选定的密钥长度，大于选定长度截断，小于则用'\0'填充，即用0X00填充字节
     *
     * @param key 密钥
     * @return AES密钥
     */
    public SecretKey getKey(byte[] key) {
        Integer keyByteLength = this.aesParam.getAesKeyEnum().getByteLength();

        // 填充key
        byte[] bytes = new byte[keyByteLength];
        if (key.length > keyByteLength) {
            System.arraycopy(key, 0, bytes, 0, keyByteLength);
        } else {
            System.arraycopy(key, 0, bytes, 0, key.length);
            Arrays.fill(bytes, key.length, keyByteLength, (byte) '\0');
        }

        // 生成算法密钥
        SecretKey secretKey = new SecretKeySpec(bytes, Constant.AES);

        return secretKey;
    }

    private void setAesParam(AESParam aesParam) {
        this.aesParam = aesParam;
    }

    public static AESCipher init() {
        AESParam aesParam = new AESParam(AESKeyEnum.KEY_256, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, null);

        AESCipher aesCipher = new AESCipher();
        aesCipher.setAesParam(aesParam);
        return aesCipher;
    }

    public static AESCipher init(AESParam aesParam) {
        AESCipher aesCipher = new AESCipher();
        aesCipher.setAesParam(aesParam);
        return aesCipher;
    }
}
