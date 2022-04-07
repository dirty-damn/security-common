package top.senseiliu.security.digest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.MessageFormat;

import org.bouncycastle.util.encoders.Hex;

/**
 * 摘要算法抽象类
 * 每次计算hash时，都会调用MessageDigest.getInstance()产生新的MessageDigest
 * 该对象及其代理对象提供的方法是线程安全的
 *
 * @author liuguanliang
 */
public abstract class AbstractDigest {

    /**
     * 用于给代理类提供重写的方法，是getInstance()的模板方法
     */
    protected abstract String getName();

    /**
     * 调用getInstance获取MessageDigest
     */
    public MessageDigest getInstance() {
        MessageDigest instance = null;
        try {
            instance =  MessageDigest.getInstance(getName());
        } catch (Exception e) {
            throw new RuntimeException(
                    MessageFormat.format("[MessageDigest]getInstance()时找不到{0}算法提供者，msg：{1}", getName(), e.getMessage()));
        }

        return instance;
    }

    /**
     * 计算摘要
     *
     * @param bytes 原始值
     * @return byte[] hash值
     */
    public byte[] digestByte(byte[] bytes) {
        return getInstance().digest(bytes);
    }

    /**
     * 计算摘要
     *
     * @param message 原始值
     * @return byte[] hash值
     */
    public byte[] digestByte(String message) {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        return digestByte(bytes);
    }

    /**
     * 计算摘要
     *
     * @param bytes 原始值
     * @param toLowerCase 输出的十六进制结果是否小写
     * @return byte[] hash值
     */
    public String digest(byte[] bytes, boolean toLowerCase) {
        byte[] digestBytes = digestByte(bytes);
        String s = Hex.toHexString(digestBytes);

        return toLowerCase ? s : s.toUpperCase();
    }

    /**
     * 计算摘要
     *
     * @param message 原始值
     * @param toLowerCase 输出的十六进制结果是否小写
     * @return String 十六进制hash值
     */
    public String digest(String message, boolean toLowerCase) {
        byte[] bytes = digestByte(message);
        String s = Hex.toHexString(bytes);

        return toLowerCase ? s : s.toUpperCase();
    }

    /**
     * 计算摘要
     *
     * @param bytes 原始值
     * @return String 十六进制hash值
     */
    public String digest(byte[] bytes) {
        return digest(bytes, true);
    }

    /**
     * 计算摘要
     *
     * @param message 原始值
     * @return String 十六进制hash值
     */
    public String digest(String message) {
        return digest(message, true);
    }
}
