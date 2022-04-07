package top.senseiliu.security.cipher.rsa;

/**
 * RSA填充模式常见的有PKCS1和OAEP(PKCS1 v2)
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
