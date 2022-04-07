package top.senseiliu.security.cipher.rsa;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import top.senseiliu.security.cipher.CipherCommon;
import top.senseiliu.security.cipher.Constant;

/**
 * RSA加密算法只有ECB模式没有其他模式
 * 参考：http://cn.voidcc.com/question/p-cadbjyyt-uq.html
 *
 * @author liuguanliang
 */
public class RSA {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public static String encrypt(RSAPaddingModeEnum RSAPaddingModeEnum, String plain, PublicKey publicKey) throws Exception {
        byte[] cipherText = encrypt(RSAPaddingModeEnum, plain.getBytes(StandardCharsets.UTF_8), publicKey);
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(RSAPaddingModeEnum RSAPaddingModeEnum, String cipherText, PrivateKey privateKey) throws Exception {
        byte[] plain = decrypt(RSAPaddingModeEnum, Base64.getDecoder().decode(cipherText), privateKey);
        return new String(plain, StandardCharsets.UTF_8);
    }

    /**
     * 加密
     * @param plain 明文字节数组
     * @param publicKey 公钥
     * @return 密文字节数组
     */
    public static byte[] encrypt(RSAPaddingModeEnum RSAPaddingModeEnum, byte[] plain, PublicKey publicKey) throws Exception {
        String algorithm = Constant.RSA + Constant.DELIMITER + "ECB" + Constant.DELIMITER + RSAPaddingModeEnum.getDesc();
        Cipher cipher = CipherCommon.getCipher(algorithm);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plain);
    }

    /**
     * 解密
     * @param cipherText 明文字节数组
     * @param privateKey 私钥
     * @return 明文字节数组
     */
    public static byte[] decrypt(RSAPaddingModeEnum RSAPaddingModeEnum, byte[] cipherText, PrivateKey privateKey) throws Exception {
        String algorithm = Constant.RSA + Constant.DELIMITER + "ECB" + Constant.DELIMITER + RSAPaddingModeEnum.getDesc();
        Cipher cipher = CipherCommon.getCipher(algorithm);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherText);
    }
}
