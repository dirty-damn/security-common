package top.senseiliu.security.cipher.aes.constant;

/**
 * 加密模式枚举类
 * ECB-电码本模式 CBC-密文分组链接方式 CFB-密文反馈模式 OFB-输出反馈模式
 * 除ECB模式外，其他模式都需要IV初始限量
 */
public enum EncryptModeEnum {
    ECB("ECB"),
    CBC("CBC"),
    CFB("CFB"),
    OFB("OFB"),
    ;

    EncryptModeEnum(String desc) {
        this.desc = desc;
    }

    private final String desc;

    public String getDesc() {
        return desc;
    }
}
