package top.senseiliu.security.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.text.MessageFormat;
import java.util.Arrays;

/**
 * To solve that you have to go to this website, download the Unlimited Strength Jurisdiction Policy Files, unzip it, go to the <java-home>/lib/security directory,
 * and replace the two files local_policy.jar and US_export_policy.jar with the two files from the download.
 *
 * Starting with Java 1.8.0_151 and 1.8.0_152 there is a new somewhat easier way to enable the unlimited strength jurisdiction policy for the JVM. Without
 * enabling this you cannot use AES-256. Since this version, it is no longer necessary to download the policy files from the Oracle website and install it. You
 * can now set the unlimited policy directly in your application with this one-liner:
 * Security.setProperty("crypto.policy", "unlimited");
 *
 * In Java 1.8.0_162, the unlimited policy is enabled by default. You no longer need to install the policy file in the JRE or set the security property crypto.policy.
 *
 * openjdk bugs: Enable unlimited cryptographic policy by default in Oracle JDK builds
 *
 * @author liuguanliang
 */
public class AES {


    public static byte[] AESEncode(AESParam aesParam, byte[] plain, byte[] key)  {
        SecretKey secretKey = getKey(key, aesParam.getAesKeyEnum());

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(aesParam.getAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Cipher]getInstance()时找不到{}算法提供者，msg：{}", aesParam.getAlgorithm(), e.getMessage()));
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

    public static byte[] AESDecode(AESParam aesParam, byte[] ciphertext, byte[] key)  {
        SecretKey secretKey = getKey(key, aesParam.getAesKeyEnum());

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(aesParam.getAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Cipher]getInstance()时找不到{}算法提供者，msg：{}", aesParam.getAlgorithm(), e.getMessage()));
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

    public static SecretKey getKey(byte[] key, AESKeyEnum aesKeyEnum) {
        // 生成原始密钥
//        KeyGenerator keygen= KeyGenerator.getInstance(KeyGeneratorEnum.AES.getDesc());
//        keygen.init(new SecureRandom(key.getBytes()));
//        SecretKey original_key = keygen.generateKey();

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
