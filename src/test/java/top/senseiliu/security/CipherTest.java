package top.senseiliu.security;

import org.junit.Assert;
import org.junit.Test;
import top.senseiliu.security.cipher.aes.AES;
import top.senseiliu.security.cipher.aes.constant.AESKeyEnum;
import top.senseiliu.security.cipher.aes.AESParam;
import top.senseiliu.security.cipher.aes.constant.EncryptModeEnum;
import top.senseiliu.security.cipher.aes.constant.PaddingModeEnum;

public class CipherTest {
    @Test
    public void cipherAlgorithm() throws Exception {
        AESParam aesParam = new AESParam(AESKeyEnum.KEY_128, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, "1234567890123456");
        byte[] bytes = AES.AESEncode(aesParam, "123".getBytes(), "123".getBytes());
        byte[] plain = AES.AESDecode(aesParam, bytes, "123".getBytes());
        Assert.assertEquals("123", new String(plain));
    }
}
