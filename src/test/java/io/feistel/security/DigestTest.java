package io.feistel.security;

import org.junit.Assert;
import org.junit.Test;
import io.feistel.security.digest.Digest;
import io.feistel.security.digest.DigestEnum;

public class DigestTest {
    @Test
    public void digestTest() {
        String digest = Digest.use(DigestEnum.MD5).digest("123".getBytes());
        Assert.assertEquals(digest, "202cb962ac59075b964b07152d234b70");

        String digest2 = Digest.use(DigestEnum.SHA256).digest("123");
        Assert.assertEquals(digest2, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

        String digest3 = Digest.use(DigestEnum.SM3).digest("123", false);
        Assert.assertEquals(digest3, "6E0F9E14344C5406A0CF5A3B4DFB665F87F4A771A31F7EDBB5C72874A32B2957");
    }
}
