package top.senseiliu.security;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.junit.Test;

public class TempTest {

    @Test
    public void rsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        System.out.println ("-----BEGIN PRIVATE KEY-----");
        // MIME Base64编码输出被映射到"A-Za-z0-9+/"字符集中，编码输出每一行不超过76个字符，而且每行以"\r\n"符结束：
        System.out.println (Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println ("-----END PRIVATE KEY-----");
    }
}
