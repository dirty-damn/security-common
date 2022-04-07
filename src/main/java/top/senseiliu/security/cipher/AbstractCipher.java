package top.senseiliu.security.cipher;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.text.MessageFormat;
import java.util.Base64;
import java.util.function.Function;

import org.bouncycastle.util.encoders.Hex;

/**
 * 加密算法抽象类
 *
 * @author liuguanliang
 */
public abstract class AbstractCipher {

    /**
     * 对字节数组所使用编解码器，默认使用Base64
     */
    private Function<byte[], String> encPostProcessHandler = encPostBase64Handler;
    private Function<String, byte[]> decPreProcessHandler = decPreBase64Handler;

    /**
     * AbstractCipher提供的编解码器，包括Base64和Hex
     */
    public static Function<byte[], String> encPostBase64Handler = o -> Base64.getEncoder().encodeToString(o);
    public static Function<String, byte[]> decPreBase64Handler = o -> Base64.getDecoder().decode(o);
    public static Function<byte[], String> encPostHexHandler = Hex::toHexString;
    public static Function<String, byte[]> decPreHexHandler = Hex::decode;

    /**
     * 有子类提供具体的算法名称，模板方法
     *
     * @return 算法名称
     */
    protected abstract String algorithm();

    /**
     * 子类实现加密算法和密钥的初始化，模板方法
     *
     * @param cipher 算法对象
     * @param key 对称密钥/公钥
     */
    protected abstract void initCipherEncrypt(Cipher cipher, Key key);

    /**
     * 子类实现解密算法和密钥的初始化，模板方法
     *
     * @param cipher 算法对象
     * @param key 对称密钥/私钥
     */
    protected abstract void initCipherDecrypt(Cipher cipher, Key key);

    /**
     * 设置编码解码器，默认使用Base64，
     * 策略模式，由调用方指定编码方式
     */
    public void codec(Function<byte[], String> encPostProcessHandler, Function<String, byte[]> decPreProcessHandler) {
        if (null == encPostProcessHandler || null == decPreProcessHandler) {
            throw new RuntimeException("[Cipher]算法编码器不能设置为null");
        }
        this.encPostProcessHandler = encPostProcessHandler;
        this.decPreProcessHandler = decPreProcessHandler;
    }

    /**
     * 加密方法
     *
     * @param plain 明文字符串
     * @param key 密钥
     * @return 编码器编码的密文
     */
    public String encrypt(String plain, Key key) {
        byte[] encrypt = encrypt(plain.getBytes(StandardCharsets.UTF_8), key);
        return encPostProcessHandler.apply(encrypt);
    }

    /**
     * 解密方法
     *
     * @param cipherText 编码器处理的密文
     * @param key 密钥
     * @return 明文字符串
     */
    public String decrypt(String cipherText, Key key) {
        byte[] decrypt = decrypt(decPreProcessHandler.apply(cipherText), key);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    /**
     * 加密方法
     *
     * @param plain 明文字节数组
     * @param key 密钥
     * @return 密文字节数组
     */
    public byte[] encrypt(byte[] plain, Key key) {
        Cipher cipher = getCipher(algorithm());

        initCipherEncrypt(cipher, key);

        byte [] bytes = null;
        try {
            bytes = cipher.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException("[Cipher]加密明文时发生异常，msg：" + e.getMessage());
        }

        return bytes;
    }

    /**
     * 解密方法
     *
     * @param cipherText 密文字节数组
     * @param key 密钥
     * @return 明文字节数组
     */
    public byte[] decrypt(byte[] cipherText, Key key) {
        Cipher cipher = getCipher(algorithm());

        initCipherDecrypt(cipher, key);

        byte [] bytes = null;
        try {
            bytes = cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new RuntimeException("[Cipher]解密明文时发生异常，msg：" + e.getMessage());
        }

        return bytes;
    }

    /**
     * 通过名称获取Cipher对象
     *
     * @param algorithm 算法名称
     * @return  Cipher对象
     */
    private static Cipher getCipher(String algorithm) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Cipher]getInstance()时找不到{0}算法提供者，msg：{1}", algorithm, e.getMessage()));
        }

        return cipher;
    }
}
