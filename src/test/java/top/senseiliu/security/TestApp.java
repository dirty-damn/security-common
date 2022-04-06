package top.senseiliu.security;

import java.io.StringReader;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Assert;
import org.junit.Test;
import top.senseiliu.security.cipher.AES;
import top.senseiliu.security.cipher.AESKeyEnum;
import top.senseiliu.security.cipher.AESParam;
import top.senseiliu.security.cipher.EncryptModeEnum;
import top.senseiliu.security.cipher.PaddingModeEnum;
import top.senseiliu.security.digest.Digest;
import top.senseiliu.security.digest.DigestEnum;
import top.senseiliu.security.key.KeyPair;
import top.senseiliu.security.key.RSAKey;
import top.senseiliu.security.key.RSAKeyEnum;

public class TestApp {
    @Test
    public void jceProviderTest() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Provider[] providers = Security.getProviders();
        System.out.println(MessageFormat.format("JCA提供者共有{0}个，如下：", providers.length));
        for (Provider p : Security.getProviders()) {
            System.out.println("\t" + p);
        }
    }

    @Test
    public void jceProviderMessageDigest() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的消息摘要算法：");
        for(String s : Security.getAlgorithms("MessageDigest")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderCipher() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的密码算法：");
        for(String s : Security.getAlgorithms("Cipher")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderKeySecureRandom() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的密钥生成器：");
        for(String s : Security.getAlgorithms("SecureRandom")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderKeyGenerator() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的密钥生成器：");
        for(String s : Security.getAlgorithms("KeyGenerator")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void jceProviderSignature() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("系统支持的签名算法：");
        for(String s : Security.getAlgorithms("Signature")){
            System.out.println("\t" + s);
        }
    }

    @Test
    public void digestTest() {
        String digest = Digest.use(DigestEnum.MD5).digest("123".getBytes());
        Assert.assertEquals(digest, "202cb962ac59075b964b07152d234b70");

        String digest2 = Digest.use(DigestEnum.SHA256).digest("123");
        Assert.assertEquals(digest2, "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

        String digest3 = Digest.use(DigestEnum.SM3).digest("123", false);
        Assert.assertEquals(digest3, "6E0F9E14344C5406A0CF5A3B4DFB665F87F4A771A31F7EDBB5C72874A32B2957");
    }

    @Test
    public void cipherAlgorithm() throws Exception {
        AESParam aesParam = new AESParam(AESKeyEnum.KEY_128, EncryptModeEnum.ECB, PaddingModeEnum.PKCS5, "1234567890123456");
        byte[] bytes = AES.AESEncode(aesParam, "123".getBytes(), "123".getBytes());
        byte[] plain = AES.AESDecode(aesParam, bytes, "123".getBytes());
        Assert.assertEquals("123", new String(plain));
    }

    @Test
    public void RSAKeyTest() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        KeyPair keyPair = RSAKey.keyPairGenerator(RSAKeyEnum.KEY_1024);

        String pkcs8 = keyPair.getRsaPvtKey().getPKCS8();
        Assert.assertNotNull(pkcs8);
        String pkcs8Pub = keyPair.getRsaPubKey().getPKCS8();
        Assert.assertNotNull(pkcs8Pub);

        String pkcs1 = keyPair.getRsaPvtKey().getPKCS1();
        Assert.assertNotNull(pkcs1);
        String pkcs1Pub = keyPair.getRsaPubKey().getPKCS1();
        Assert.assertNotNull(pkcs1Pub);

        String pemPKCS8 = "-----BEGIN PRIVATE KEY-----\r\n" +
                "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAId7rfXopAhYF6Ee\r\n" +
                "UkGIUP426+inmWFYLS7lsvgQezmC0CduaQcy4QrRTGi6m/hB0uY6/g0nv2qpq2SQ\r\n" +
                "LSpro8EKtG98kxroTsgIeEfEfPpr1cR1FUq4wmbFH2XliwXEXwgtPLp39MMTHQbY\r\n" +
                "VPs36wqIQkxukSBdqt7AHOkw2VdTAgMBAAECgYBN7yxTj56EGkCFcw64GbUVdvxf\r\n" +
                "WcGWSIW9O26m2bw4ifI5LH8IIBFqCpmciPPda+fofjjT0nB+59jqwTDp/P811wl5\r\n" +
                "mp+3lGEiXSedNOWNGiKQhjytoL/APbZgYZOGPRX45AQNx7zRaT9sdng8KopSrCO6\r\n" +
                "rRaGtQku/BUIwWn8qQJBAPU4aXuAbf0j0QlzeSIbXKMJrYy2aEr46rk8juL60W2Y\r\n" +
                "uzqYlvp1k1UdIaZ0wxMGdtZ712AQENjKZLvjKMRotScCQQCNcFbW1UJ2FDRSBVPc\r\n" +
                "7okYbudqVcyurrrC9RJ0nNKcYIzHovAlzirVBV0cfoSn2on3lIbpFGDCIsl4zNuy\r\n" +
                "0d/1AkEA3ZpKMNKiEwZADPNuf3UMpUXEsYnR/BawQA/K7LJPemRwpoZowhRovZ0i\r\n" +
                "4MNZ2qKX2EJ4IxbBsrhMikLBf6VENwJBAIsN11J/eEf+tTGuazTaj46l+n5gvEtB\r\n" +
                "HfxuVSawx59WjRH474E7oICuNUy+Vk1wXhQ6wiiFEFvNN6a8QYMdM8ECQQCWNko/\r\n" +
                "PQdD0/+uno58It2Uh0tcWtfsrt0O+6Ny2EjgQijeoxTA+o0sqdDb0P45DQYsXBv3\r\n" +
                "NhYB2GS64LhY5XIz\r\n" +
                "-----END PRIVATE KEY-----" +
                "\r\n";
        String pemPKCS1 = "-----BEGIN RSA PRIVATE KEY-----\r\n" +
                "MIICXgIBAAKBgQCHe6316KQIWBehHlJBiFD+Nuvop5lhWC0u5bL4EHs5gtAnbmkH\r\n" +
                "MuEK0Uxoupv4QdLmOv4NJ79qqatkkC0qa6PBCrRvfJMa6E7ICHhHxHz6a9XEdRVK\r\n" +
                "uMJmxR9l5YsFxF8ILTy6d/TDEx0G2FT7N+sKiEJMbpEgXarewBzpMNlXUwIDAQAB\r\n" +
                "AoGATe8sU4+ehBpAhXMOuBm1FXb8X1nBlkiFvTtuptm8OInyOSx/CCARagqZnIjz\r\n" +
                "3Wvn6H4409JwfufY6sEw6fz/NdcJeZqft5RhIl0nnTTljRoikIY8raC/wD22YGGT\r\n" +
                "hj0V+OQEDce80Wk/bHZ4PCqKUqwjuq0WhrUJLvwVCMFp/KkCQQD1OGl7gG39I9EJ\r\n" +
                "c3kiG1yjCa2MtmhK+Oq5PI7i+tFtmLs6mJb6dZNVHSGmdMMTBnbWe9dgEBDYymS7\r\n" +
                "4yjEaLUnAkEAjXBW1tVCdhQ0UgVT3O6JGG7nalXMrq66wvUSdJzSnGCMx6LwJc4q\r\n" +
                "1QVdHH6Ep9qJ95SG6RRgwiLJeMzbstHf9QJBAN2aSjDSohMGQAzzbn91DKVFxLGJ\r\n" +
                "0fwWsEAPyuyyT3pkcKaGaMIUaL2dIuDDWdqil9hCeCMWwbK4TIpCwX+lRDcCQQCL\r\n" +
                "DddSf3hH/rUxrms02o+Opfp+YLxLQR38blUmsMefVo0R+O+BO6CArjVMvlZNcF4U\r\n" +
                "OsIohRBbzTemvEGDHTPBAkEAljZKPz0HQ9P/rp6OfCLdlIdLXFrX7K7dDvujcthI\r\n" +
                "4EIo3qMUwPqNLKnQ29D+OQ0GLFwb9zYWAdhkuuC4WOVyMw==\r\n" +
                "-----END RSA PRIVATE KEY-----" +
                "\r\n";
        KeyPair.RSAPvtKey rsaPvtKey = KeyPair.RSAPvtKey.instanceFromPem(pemPKCS8);
        Assert.assertEquals(rsaPvtKey.getPKCS8(), pemPKCS8);
        KeyPair.RSAPvtKey rsaPvtKey2 = KeyPair.RSAPvtKey.instanceFromPem(pemPKCS1);
        Assert.assertEquals(rsaPvtKey2.getPKCS1(), pemPKCS1);

        String pemPKCS8Pub = "-----BEGIN PUBLIC KEY-----\r\n" +
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHe6316KQIWBehHlJBiFD+Nuvo\r\n" +
                "p5lhWC0u5bL4EHs5gtAnbmkHMuEK0Uxoupv4QdLmOv4NJ79qqatkkC0qa6PBCrRv\r\n" +
                "fJMa6E7ICHhHxHz6a9XEdRVKuMJmxR9l5YsFxF8ILTy6d/TDEx0G2FT7N+sKiEJM\r\n" +
                "bpEgXarewBzpMNlXUwIDAQAB\r\n" +
                "-----END PUBLIC KEY-----" +
                "\r\n";
        String pemPKCS1Pub = "-----BEGIN RSA PUBLIC KEY-----\r\n" +
                "MIGJAoGBAId7rfXopAhYF6EeUkGIUP426+inmWFYLS7lsvgQezmC0CduaQcy4QrR\r\n" +
                "TGi6m/hB0uY6/g0nv2qpq2SQLSpro8EKtG98kxroTsgIeEfEfPpr1cR1FUq4wmbF\r\n" +
                "H2XliwXEXwgtPLp39MMTHQbYVPs36wqIQkxukSBdqt7AHOkw2VdTAgMBAAE=\r\n" +
                "-----END RSA PUBLIC KEY-----" +
                "\r\n";
        KeyPair.RSAPubKey rsaPubKey = KeyPair.RSAPubKey.instanceFromPem(pemPKCS8Pub);
        Assert.assertEquals(rsaPubKey.getPKCS8(), pemPKCS8Pub);
        KeyPair.RSAPubKey rsaPubKey1 = KeyPair.RSAPubKey.instanceFromPem(pemPKCS1Pub);
        Assert.assertEquals(rsaPubKey1.getPKCS1(), pemPKCS1Pub);
    }

}
