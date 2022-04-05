package top.senseiliu.security;

import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import top.senseiliu.security.cipher.AES;
import top.senseiliu.security.cipher.AESKeyEnum;
import top.senseiliu.security.cipher.AESParam;
import top.senseiliu.security.cipher.EncryptModeEnum;
import top.senseiliu.security.cipher.PaddingModeEnum;
import top.senseiliu.security.digest.Digest;
import top.senseiliu.security.digest.DigestEnum;

public class TestApp {
    @Test
    public void jceProviderTest() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Provider[] providers = Security.getProviders();
        System.out.println(MessageFormat.format("JCA提供者共有{0}个，如下：", providers.length));
        for (Provider p : Security.getProviders()) {
            System.out.println("\t" + p);
        }
    }

    @Test
    public void jceProviderMessageDigest() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的消息摘要算法：");
        for(String s : Security.getAlgorithms("MessageDigest")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderCipher() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的密码算法：");
        for(String s : Security.getAlgorithms("Cipher")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderKeySecureRandom() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的密钥生成器：");
        for(String s : Security.getAlgorithms("SecureRandom")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderKeyGenerator() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的密钥生成器：");
        for(String s : Security.getAlgorithms("KeyGenerator")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void digestTest() {
        String digest = Digest.use(DigestEnum.MD5).digest("123".getBytes());
        Assert.assertEquals(digest, "202cb962ac59075b964b07152d234b70");

        String digest2 = Digest.use(DigestEnum.SHA256).digest("123");
        Assert.assertEquals(digest2, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

        String digest3 = Digest.use(DigestEnum.SM3).digest("123", false);
        Assert.assertEquals(digest3, "6E0F9E14344C5406A0CF5A3B4DFB665F87F4A771A31F7EDBB5C72874A32B2957");
    }

    @Test
    public void cipherAlgorithm() throws Exception {
        AESParam aesParam = new AESParam(AESKeyEnum.KEY_128, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, "1234567890123456");

        byte[] bytes = AES.AESEncode(aesParam, "123".getBytes(), "123".getBytes());
        byte[] plain = AES.AESDecode(aesParam, bytes, "123".getBytes());
    }
}
