package top.senseiliu.security;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import top.senseiliu.security.cipher.aes.AES;
import top.senseiliu.security.cipher.aes.constant.AESKeyEnum;
import top.senseiliu.security.cipher.aes.AESParam;
import top.senseiliu.security.cipher.aes.constant.EncryptModeEnum;
import top.senseiliu.security.cipher.aes.constant.PaddingModeEnum;
import top.senseiliu.security.cipher.rsa.RSA;
import top.senseiliu.security.cipher.rsa.RSAPaddingModeEnum;

public class CipherTest {
    @Test
    public void AESTest() throws Exception {
        AESParam aesParam = new AESParam(AESKeyEnum.KEY_128, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, "1234567890123456");
        byte[] bytes = AES.AESEncode(aesParam, "123".getBytes(), "123".getBytes());
        byte[] plain = AES.AESDecode(aesParam, bytes, "123".getBytes());
        Assert.assertEquals("123", new String(plain));
    }

    @Test
    public void RSATest() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        String encrypt = RSA.encrypt(RSAPaddingModeEnum.OAEP, "123", SignTest.pub().getPublicKey());
        String decrypt = RSA.decrypt(RSAPaddingModeEnum.OAEP, encrypt, SignTest.pvt().getPrivateKey());
        System.out.println(encrypt);
        Assert.assertEquals(decrypt, "123");
    }
}
