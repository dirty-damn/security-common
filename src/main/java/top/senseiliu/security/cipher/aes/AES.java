package top.senseiliu.security.cipher.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.text.MessageFormat;
import java.util.Arrays;

import top.senseiliu.security.cipher.Constant;
import top.senseiliu.security.cipher.aes.constant.AESKeyEnum;
import top.senseiliu.security.cipher.aes.constant.EncryptModeEnum;

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
public final class AES {

    /**
     * AES加密方法
     *
     * @param aesParam AES算法参数
     * @param plain 明文字节数组
     * @param key 密钥字节数组
     * @return 密文字节数组
     */
    public static byte[] AESEncode(AESParam aesParam, byte[] plain, byte[] key)  {
        SecretKey secretKey = getKey(key, aesParam.getAesKeyEnum());

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(aesParam.getAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Cipher]getInstance()时找不到{0}算法提供者，msg：{1}", aesParam.getAlgorithm(), e.getMessage()));
        }

        if (EncryptModeEnum.ECB.equals(aesParam.getEncryptModeEnum())) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
            }
        } else {
            if ((null == aesParam.getIv() || aesParam.getIv().isEmpty())) {
                throw new RuntimeException("[Cipher]除ECB加密模式外，其他模式都需要IV初始偏移量");
            }

            IvParameterSpec iv = new IvParameterSpec(aesParam.getIv().getBytes());
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            } catch (Exception e) {
                throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
            }
        }

        byte [] byte_AES = null;
        try {
            byte_AES = cipher.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException("[Cipher]加密明文时发送异常，msg：" + e.getMessage());
        }

        return byte_AES;
    }

    /**
     * AES解密方法
     *
     * @param aesParam AES算法参数
     * @param ciphertext 密文字节数组
     * @param key 密钥字节数组
     * @return 明文字节数组
     */
    public static byte[] AESDecode(AESParam aesParam, byte[] ciphertext, byte[] key)  {
        SecretKey secretKey = getKey(key, aesParam.getAesKeyEnum());

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(aesParam.getAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Cipher]getInstance()时找不到{0}算法提供者，msg：{1}", aesParam.getAlgorithm(), e.getMessage()));
        }

        if (EncryptModeEnum.ECB.equals(aesParam.getEncryptModeEnum())) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } catch (InvalidKeyException e) {
                throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
            }
        } else {
            if ((null == aesParam.getIv() || aesParam.getIv().isEmpty())) {
                throw new RuntimeException("[Cipher]除ECB加密模式外，其他模式都需要IV初始偏移量");
            }

            IvParameterSpec iv = new IvParameterSpec(aesParam.getIv().getBytes());
            try {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            } catch (Exception e) {
                throw new RuntimeException("[Cipher]加密密钥异常，msg：" + e.getMessage());
            }
        }

        byte [] plain = null;
        try {
            plain = cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("[Cipher]解密明文时发送异常，msg：" + e.getMessage());
        }

        return plain;
    }

    /**
     * 填充key，根据选定的密钥长度，大于选定长度截断，小于则用'\0'填充，即用0X00填充字节
     *
     * @param key 密钥
     * @param aesKeyEnum 密钥长度枚举
     * @return AES密钥
     */
    private static SecretKey getKey(byte[] key, AESKeyEnum aesKeyEnum) {
        Integer keyByteLength = aesKeyEnum.getByteLength();

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
}
