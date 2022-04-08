package io.feistel.security.digest;

/**
 * 摘要枚举值
 * 枚举字符串是JCA提供者提供摘要算法实现
 *
 * 包括openssl 1.1.1m能提供的所有摘要算法，除了mdc2
 * Message Digest commands (see the `dgst' command for more details)
 * blake2b512        blake2s256        gost              md4
 * md5               --mdc2            rmd160            sha1
 * sha224            sha256            sha3-224          sha3-256
 * sha3-384          sha3-512          sha384            sha512
 * sha512-224        sha512-256        shake128          shake256
 * sm3
 *
 * @author liuguanliang
 */
public enum DigestEnum {

    BLAKE2B512("BLAKE2B-512"),
    BLAKE2S512("BLAKE2S-256"),
    GOST("GOST3411"),
    MD4("MD4"),
    MD5("MD5"),
    RMD128("RIPEMD128"),
    RMD160("RIPEMD160"),
    RMD256("RIPEMD256"),
    // SHA1
    SHA1("SHA-1"),
    // SHA2，SHA-224、SHA-256、SHA-384，和SHA-512并称为SHA2
    SHA224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),
    // SHA3，SHA3-224、SHA3-256、SHA3-384，和SHA3-512并称为SHA3
    SHA3_224("SHA3-224"),
    SHA3_256("SHA3-256"),
    SHA3_384("SHA3-384"),
    SHA3_512("SHA3-512"),
    // SHA512
    SHA512_256("SHA-512/256"),
    SHA512_224("SHA-512/224"),
    // SHAKE
    SHAKE128("SHAKE128-256"),
    SHAKE256("SHAKE256-512"),
    // 国密hash
    SM3("SM3"),
    ;

    DigestEnum(String desc) {
        this.desc = desc;
    }

    private final String desc;

    public String getDesc() {
        return desc;
    }
}
