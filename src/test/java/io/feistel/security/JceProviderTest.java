package io.feistel.security;

import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class JceProviderTest {
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
    public void jceProviderSignature() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的签名算法：");
        for(String s : Security.getAlgorithms("Signature")){
            System.out.println("\t" + s);
        }
    }
}
