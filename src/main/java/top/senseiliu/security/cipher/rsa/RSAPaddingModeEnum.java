package top.senseiliu.security.cipher.rsa;

/**
 * RSA填充模式常见的有PKCS1和OAEP(PKCS1 v2)
 *
 * 还有不常见的填充，参考：https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
 * OAEPWithMD5AndMGF1Padding
 * OAEPWithSHA1AndMGF1Padding
 * OAEPWithSHA-1AndMGF1Padding
 * OAEPWithSHA-224AndMGF1Padding
 * OAEPWithSHA-256AndMGF1Padding
 * OAEPWithSHA-384AndMGF1Padding
 * OAEPWithSHA-512AndMGF1Padding
 * OAEPWithSHA-512/224AndMGF1Padding
 * OAEPWithSHA-512/2256ndMGF1Padding
 *
 * @author liuguanliang
 */
public enum RSAPaddingModeEnum {
    NoPadding("NoPadding"),
    PKCS1("PKCS1Padding"),
    OAEP("OAEPPadding"),
    ;

    RSAPaddingModeEnum(String desc) {
        this.desc = desc;
    }

    private final String desc;

    public String getDesc() {
        return desc;
    }
}
