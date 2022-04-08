package io.feistel.security.signature;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.text.MessageFormat;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 签名算法
 *
 * @author liuguanliang
 */
public class Sign {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    /**
     * 签名
     *
     * @param signatureEnum 签名算法
     * @param content 待签名字符串
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(SignatureEnum signatureEnum, String content, PrivateKey privateKey) {
        byte[] sign = sign(signatureEnum, content.getBytes(StandardCharsets.UTF_8), privateKey);
        return Base64.getEncoder().encodeToString(sign);
    }

    /**
     * 验签
     *
     * @param signatureEnum 签名算法
     * @param content 待签名字符串
     * @param sign 签名
     * @param pubKey 公钥
     * @return 成功返回true，反之
     */
    public static boolean verify(SignatureEnum signatureEnum, String content, String sign, PublicKey pubKey) {
        return verify(signatureEnum, content.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(sign), pubKey);
    }

    /**
     * 签名
     *
     * @param signatureEnum 签名算法
     * @param content 待签名字节数组
     * @param privateKey 私钥
     * @return 签名
     */
    public static byte[] sign(SignatureEnum signatureEnum, byte[] content, PrivateKey privateKey) {
        Signature signature = null;
        try {
            signature = Signature.getInstance(signatureEnum.getDesc());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Signature]getInstance()时找不到{0}签名算法提供者，msg：{1}", signatureEnum.getDesc(), e.getMessage()));
        }

        byte[] sign = null;
        try {
            signature.initSign(privateKey);
            signature.update(content);
            sign = signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Signature]{0}签名时发生异常，msg：{1}", signatureEnum.getDesc(), e.getMessage()));
        }

        return sign;
    }

    /**
     * 验签
     *
     * @param signatureEnum 签名算法
     * @param content 待签名字节数组
     * @param sign    签名
     * @param pubKey  公钥
     * @return 成功返回true，反之
     */
    public static boolean verify(SignatureEnum signatureEnum, byte[] content, byte[] sign, PublicKey pubKey) {
        Signature signature = null;
        try {
            signature = Signature.getInstance(signatureEnum.getDesc());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Signature]getInstance()时找不到{0}签名算法提供者，msg：{1}", signatureEnum.getDesc(), e.getMessage()));
        }

        boolean verify = false;
        try {
            signature.initVerify(pubKey);
            signature.update(content);
            verify = signature.verify(sign);
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[Signature]{0}验签时发生异常，msg：{1}", signatureEnum.getDesc(), e.getMessage()));
        }

        return verify;
    }
}
