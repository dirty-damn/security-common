package top.senseiliu.security.key;

import java.io.StringReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

@Data
@AllArgsConstructor
public class KeyPair {
    private RSAPubKey rsaPubKey;
    private RSAPvtKey rsaPvtKey;

    public static class RSAPubKey extends AbstractKey {
        public RSAPubKey(byte[] rsaPubKey) {
            super(rsaPubKey, true);
        }

        public static byte[] PKCS1ToPKCS8(byte[] keyBytes) {
            org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPub = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(keyBytes);

            KeyFactory keyFactory = null;
            try {
                keyFactory = KeyFactory.getInstance(KeyConstant.RSA);
            } catch (Exception e) {
                throw new RuntimeException(
                        MessageFormat.format("[KeyFactory]getInstance()时找不到{}的KeyFactory提供者，msg：{}", KeyConstant.RSA, e.getMessage()));
            }

            PublicKey publicKey = null;
            try {
                publicKey =  keyFactory.generatePublic(new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent()));
            } catch (Exception e) {
                throw new RuntimeException("[ASN1InputStream]公钥转PKCS8时发生异常，msg：{}" + e.getMessage());
            }

            return publicKey.getEncoded();
        }

        public static RSAPubKey instanceFromPem(String pem) {
            PemObject pemObject = getPemObject(pem);

            String type = pemObject.getType();
            if (!KeyConstant.PUB_PKCS8.equals(type) && !KeyConstant.PUB_PKCS1.equals(type)) {
                throw new RuntimeException("[PemObject]仅支持RSA的PKCS1和PKCS8类型的公钥格式");
            }

            byte[] content = pemObject.getContent();
            if (KeyConstant.PUB_PKCS1.equals(type)) {
                content = RSAPubKey.PKCS1ToPKCS8(content);
            }

            return new RSAPubKey(content);
        }
    }

    public static class RSAPvtKey extends AbstractKey {
        public RSAPvtKey(byte[] rsaPvtKey) {
            super(rsaPvtKey, false);
        }

        public static byte[] PKCS1ToPKCS8(byte[] keyBytes) {
            byte[] pkcs8Bytes = null;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag);
            try {
                ASN1Object asn1Object = ASN1ObjectIdentifier.fromByteArray(keyBytes);
                PrivateKeyInfo privKeyInfo = new PrivateKeyInfo(algorithmIdentifier, asn1Object);
                pkcs8Bytes = privKeyInfo.getEncoded();
            } catch (Exception e) {
                throw new RuntimeException("[KeyFactory]转PKCS8私钥时发生异常，msg：{}" + e.getMessage());
            }

            return pkcs8Bytes;
        }

        public static RSAPvtKey instanceFromPem(String pem) {
            PemObject pemObject = getPemObject(pem);

            String type = pemObject.getType();
            if (!KeyConstant.PVT_PKCS8.equals(type) && !KeyConstant.PVT_PKCS1.equals(type)) {
                throw new RuntimeException("[PemObject]仅支持RSA的PKCS1和PKCS8类型的私钥格式");
            }

            byte[] content = pemObject.getContent();
            if (KeyConstant.PVT_PKCS1.equals(type)) {
                content = RSAPvtKey.PKCS1ToPKCS8(content);
            }

            return new RSAPvtKey(content);
        }
    }
}
