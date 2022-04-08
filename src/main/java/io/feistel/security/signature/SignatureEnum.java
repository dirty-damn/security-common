package io.feistel.security.signature;

/**
 * 签名算法枚举
 *
 * @author liuguanliang
 */
public enum SignatureEnum {
    // SHA1
    SHA1WithRSA("SHA1WithRSA"),
    // SHA2
    SHA224WITHRSA("SHA224WITHRSA"),
    SHA256WITHRSA("SHA256WITHRSA"),
    SHA384WITHRSA("SHA384WITHRSA"),
    SHA512WITHRSA("SHA512WITHRSA"),
    // SHA3
    SHA3_224WITHRSA("SHA3-224WITHRSA"),
    SHA3_384WITHRSA("SHA3-384WITHRSA"),
    SHA3_256WITHRSA("SHA3-256WITHRSA"),
    SHA3_512WITHRSA("SHA3-512WITHRSA"),
    // MD5
    MD5WITHRSA("MD5WITHRSA"),
    // MD5 SHA1
    MD5ANDSHA1WITHRSA("MD5ANDSHA1WITHRSA"),
    // RMD
    RMD128WITHRSA("RMD128WITHRSA"),
    RMD160WITHRSA("RMD160WITHRSA"),
    RMD256WITHRSA("RMD256WITHRSA"),
    ;

    SignatureEnum(String desc) {
        this.desc = desc;
    }

    private final String desc;

    public String getDesc() {
        return desc;
    }
}
