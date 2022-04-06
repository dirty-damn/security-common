package top.senseiliu.security.key;

public enum RSAKeyEnum {
    KEY_1024(1024),
    KEY_2048(2048),
    ;

    RSAKeyEnum(Integer keyLength) {
        this.keyLength = keyLength;
    }

    private final Integer keyLength;

    public Integer getKeyLength() {
        return keyLength;
    }
}
