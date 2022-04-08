package io.feistel.security.cipher.aes.constant;

/**
 * AES密钥长度枚举
 *
 * @author liuguanliang
 */
public enum AESKeyEnum {
    KEY_128(128, 16),
    KEY_192(192, 24),
    KEY_256(256, 32),
    ;

    AESKeyEnum(Integer desc, Integer byteLength) {
        this.desc = desc;
        this.byteLength = byteLength;
    }

    private final Integer desc;
    private final Integer byteLength;

    public Integer getDesc() {
        return desc;
    }

    public Integer getByteLength() {
        return byteLength;
    }
}
