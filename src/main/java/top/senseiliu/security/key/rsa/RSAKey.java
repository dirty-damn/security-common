package top.senseiliu.security.key.rsa;

import java.io.StringReader;
import java.io.StringWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * RSA密钥抽象类
 * 包括获取PKCS1和PKCS8的字节数据和PEM格式字符串
 * 此外还有读取PEM以获得PEM对象的功能
 *
 * @author liuguanliang
 */
public abstract class RSAKey {
    // 存放PKCS8的字节数据
    protected final byte[] keyBytes;

    /**
     * 子类在构造的时候需要传入
     *
     * @param keyBytes PKCS8格式的字节数组
     */
    public RSAKey(byte[] keyBytes) {
        this.keyBytes = keyBytes;
    }

    /**
     * 获取PKCS8格式的密钥
     *
     * @return 返回PKCS8格式的字节数组
     */
    public byte[] getBytesPKCS8() {
        return this.keyBytes;
    }

    /**
     * 获取PKCS1格式的密钥，子类需要重写
     *
     * @return 返回PKCS1格式的字节数组
     */
    public abstract byte[] getBytesPKCS1();

    /**
     * 获取PEM格式的PKCS8的公私钥
     *
     * @return 返回PKCS8格式的PEM
     */
    public String getPemPKCS8() {
        return getPem(pemPKCS8Header(), getBytesPKCS8());
    }

    /**
     * 获取PEM格式的PKCS1的公私钥
     *
     * @return 返回PKCS8格式的PEM
     */
    public String getPemPKCS1() {
        return getPem(pemPKCS1Header(), getBytesPKCS1());
    }

    /**
     * PKCS8格式的PEM密钥头信息，子类需要重写
     *
     * @return 返回PKCS8格式的PEM头信息
     */
    protected abstract String pemPKCS8Header();

    /**
     * PKCS1格式的PEM密钥头信息，子类需要重写
     *
     * @return 返回PKCS1格式的PEM头信息
     */
    protected abstract String pemPKCS1Header();

    private String getPem(String header, byte[] bytes) {
        PemObject pemObject = new PemObject(header, bytes);
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writeObject(pemObject);
        } catch (Exception e) {
            throw new RuntimeException("[PemWriter]写PEM时发生异常，msg：{0}" + e.getMessage());
        }

        return stringWriter.toString();
    }

    /**
     * 读取PEM格式的字符串
     *
     * @param pem pem的密钥
     * @return Pem对象
     */
    public static PemObject readPem(String pem) {
        if (null == pem || pem.isEmpty()) {
            throw new RuntimeException("[PemObject]参数pem不能为空");
        }

        StringReader stringReader = new StringReader(pem);
        PemReader pemReader = new PemReader(stringReader);
        PemObject pemObject = null;
        try {
            pemObject = pemReader.readPemObject();
        } catch (Exception e) {
            throw new RuntimeException("[PemObject]读取pem时发生了异常，msg：{0}" + e.getMessage());
        }
        return pemObject;
    }

}
