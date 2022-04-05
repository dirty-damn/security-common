package top.senseiliu.security.cipher;

/**
 * 填充模式枚举类型
 * 以支持的有：
 * PKCS5，每个字节填充为须要填充的字节长度
 * NoPadding，即不填充，要求明文的长度，必须是加密算法分组长度的整数倍
 * ISO10126，最初一个字节填充为须要填充的字节长度，其余字节填充随机数
 *
 * 不支持的有：
 * ANSI X9.23，最初一个字节填充为须要填充的字节长度，其余字节填充0
 * ISO/IEC 7816-4，第一个字节填充固定值80，其余字节填充0。若只需填充一个字节，则间接填充80
 * Zero Padding，每个字节填充为0
 */
public enum PaddingModeEnum {
    NoPadding("NoPadding"),
    PKCS5("PKCS5Padding"),
    ISO10126("ISO10126Padding "),
    ;

    PaddingModeEnum(String desc) {
        this.desc = desc;
    }

    private final String desc;

    public String getDesc() {
        return desc;
    }
}
