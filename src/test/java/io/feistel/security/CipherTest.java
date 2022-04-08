package io.feistel.security;

import io.feistel.security.cipher.aes.AESCipher;
import io.feistel.security.cipher.aes.AESParam;
import io.feistel.security.cipher.aes.constant.AESKeyEnum;
import io.feistel.security.cipher.aes.constant.EncryptModeEnum;
import io.feistel.security.cipher.aes.constant.PaddingModeEnum;
import org.junit.Assert;
import org.junit.Test;
import io.feistel.security.cipher.AbstractCipher;
import io.feistel.security.cipher.rsa.RSACipher;
import io.feistel.security.cipher.rsa.RSAPaddingModeEnum;

public class CipherTest {
    @Test
    public void AESTest() {
        AESCipher aesCipher = AESCipher.init();
        String encrypt = aesCipher.encrypt("123", aesCipher.getKey("123".getBytes()));
        String decrypt = aesCipher.decrypt(encrypt, aesCipher.getKey("123".getBytes()));
        Assert.assertEquals(decrypt, "123");

        AESParam aesParam = new AESParam(AESKeyEnum.KEY_128, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, "1234567890123456");
        AESCipher aesCipher1 = AESCipher.init(aesParam);
        // 指定编解码器
        String encrypt1 = aesCipher1.encrypt("123", aesCipher1.getKey("123".getBytes()), AbstractCipher.encPostHexHandler);
        String decrypt1 = aesCipher1.decrypt(encrypt1, aesCipher1.getKey("123".getBytes()), AbstractCipher.decPreHexHandler);
        Assert.assertEquals(decrypt1, "123");
    }

    @Test
    public void RSATest() {
        RSACipher rsaCipher = RSACipher.init();
        String encrypt = rsaCipher.encrypt("123", SignTest.pub().getPublicKey());
        String decrypt = rsaCipher.decrypt(encrypt, SignTest.pvt().getPrivateKey());
        Assert.assertEquals(decrypt, "123");

        RSACipher rsaCipher1 = RSACipher.init(RSAPaddingModeEnum.OAEP);
        // 指定编解码器
        String encrypt1 = rsaCipher1.encrypt("123", SignTest.pub().getPublicKey(), AbstractCipher.encPostHexHandler);
        String decrypt1 = rsaCipher1.decrypt(encrypt1, SignTest.pvt().getPrivateKey(), AbstractCipher.decPreHexHandler);
        Assert.assertEquals(decrypt1, "123");
    }
}
