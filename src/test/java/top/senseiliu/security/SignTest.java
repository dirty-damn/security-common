package top.senseiliu.security;

import org.junit.Assert;
import org.junit.Test;
import top.senseiliu.security.key.rsa.RSAPubRSAKey;
import top.senseiliu.security.key.rsa.RSAPvtRSAKey;
import top.senseiliu.security.signature.Sign;
import top.senseiliu.security.signature.SignatureEnum;

public class SignTest {
    public static RSAPvtRSAKey pvt() {
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
        RSAPvtRSAKey rsaPvtKey = RSAPvtRSAKey.instanceFromPem(pemPKCS8);
        return rsaPvtKey;
    }

    public static RSAPubRSAKey pub() {
        String pemPKCS8Pub = "-----BEGIN PUBLIC KEY-----\r\n" +
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHe6316KQIWBehHlJBiFD+Nuvo\r\n" +
                "p5lhWC0u5bL4EHs5gtAnbmkHMuEK0Uxoupv4QdLmOv4NJ79qqatkkC0qa6PBCrRv\r\n" +
                "fJMa6E7ICHhHxHz6a9XEdRVKuMJmxR9l5YsFxF8ILTy6d/TDEx0G2FT7N+sKiEJM\r\n" +
                "bpEgXarewBzpMNlXUwIDAQAB\r\n" +
                "-----END PUBLIC KEY-----" +
                "\r\n";
        RSAPubRSAKey rsaPubKey = RSAPubRSAKey.instanceFromPem(pemPKCS8Pub);
        return rsaPubKey;
    }

    @Test
    public void signTest() {
        String sign = Sign.sign(SignatureEnum.SHA1WithRSA, "123", pvt().getPrivateKey());
        Assert.assertEquals(sign, "feXkZtkzvvwGa+qns+eBH+yhZgKMi2YREBZzqNGW9s44jcAeXv5jzBieMITEz7krS9unIZx10t2BCfHgXURx6DAji7l8oQSLTHXfShf5GQhhRf05pMvvaIU1gUe9hjPVUlVqejJ7OQryVcewbZE+AKvWuN8sCLPDF0X7E9+zlAE=");
        boolean verify = Sign.verify(SignatureEnum.SHA1WithRSA, "123", sign, pub().getPublicKey());
        Assert.assertTrue(verify);

        String sign1 = Sign.sign(SignatureEnum.MD5WITHRSA, "123", pvt().getPrivateKey());
        Assert.assertEquals(sign1, "AzvFOYVbJ1wTvia66aT9whX/m9Qjx+oQsed3fP2LSbB8eAjU/j9ZXHLudqw/i+bLKM3HcBwXhZp+x9zPubYf8JO2ltSa/27SyFFfXWegJZqgC+sgJt5aI9D6C/G56gbUVjWBFy0SsqeRL3L2AQVjJFDoAeg2aHbs+0TPtleRVyo=");
        boolean verify1 = Sign.verify(SignatureEnum.MD5WITHRSA, "123", sign1, pub().getPublicKey());
        Assert.assertTrue(verify1);

        String sign2 = Sign.sign(SignatureEnum.RMD160WITHRSA, "123", pvt().getPrivateKey());
        Assert.assertEquals(sign2, "Vnx8ofW1+7cdfsLZ0IjpVHkh03jPwJt1lf4TB35qlN8EVXnooZlwKdNMfNXHsZDyhcWgO62Z+njWEPetTEKA74HFfrYCtAnrQa9XiRjBa3ApSURzPWqmnVLFqjkYz2O2OUGXulYnJ121LbBlXsJNrHUckryX3YVZr7u7Im9jdiM=");
        boolean verify2 = Sign.verify(SignatureEnum.RMD160WITHRSA, "123", sign2, pub().getPublicKey());
        Assert.assertTrue(verify2);
    }
}
