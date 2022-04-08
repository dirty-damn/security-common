package io.feistel.security.cipher;

import javax.crypto.Cipher;
import java.text.MessageFormat;

public final class CipherCommon {

    public static Cipher getCipher(String algorithm) {
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
