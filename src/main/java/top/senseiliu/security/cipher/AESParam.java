package top.senseiliu.security.cipher;

import javax.crypto.spec.IvParameterSpec;

/**
 * 构造AES算法需要的参数
 *
 * @author liuguanliang
 */
public class AESParam {
    private AESKeyEnum aesKeyEnum;
    private EncryptModeEnum encryptModeEnum;
    private PaddingModeEnum paddingModeEnum;
    private String iv;

    public AESParam(AESKeyEnum aesKeyEnum, EncryptModeEnum encryptModeEnum, PaddingModeEnum paddingModeEnum, String iv) {
        this.aesKeyEnum = aesKeyEnum;
        this.encryptModeEnum = encryptModeEnum;
        this.paddingModeEnum = paddingModeEnum;
        this.iv = iv;
    }

    /**
     * 获取AES算法名称
     *
     * @return String 算法名称 AES/模式/填充
     */
    public String getAlgorithm() {
        return Constant.AES + Constant.DELIMITER + this.encryptModeEnum.getDesc() + Constant.DELIMITER + this.paddingModeEnum.getDesc();
    }

    public AESKeyEnum getAesKeyEnum() {
        return aesKeyEnum;
    }

    public void setAesKeyEnum(AESKeyEnum aesKeyEnum) {
        this.aesKeyEnum = aesKeyEnum;
    }

    public EncryptModeEnum getEncryptModeEnum() {
        return encryptModeEnum;
    }

    public void setEncryptModeEnum(EncryptModeEnum encryptModeEnum) {
        this.encryptModeEnum = encryptModeEnum;
    }

    public PaddingModeEnum getPaddingModeEnum() {
        return paddingModeEnum;
    }

    public void setPaddingModeEnum(PaddingModeEnum paddingModeEnum) {
        this.paddingModeEnum = paddingModeEnum;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}
