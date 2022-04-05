package top.senseiliu.security.cipher;

public enum CipherEnum {

    // AES 128
    QWAER("AES/ECB/PKCS5Padding"),
    ;

    CipherEnum(String desc) {
        this.desc = desc;
    }

    private final String desc;

    public String getDesc() {
        return desc;
    }
}
