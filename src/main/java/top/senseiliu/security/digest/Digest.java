package top.senseiliu.security.digest;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import net.sf.cglib.proxy.Enhancer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import top.senseiliu.security.digest.interceptor.DigestMethodInterceptor;

/**
 * 摘要算法使用入口，使用use指定摘要算法
 * 使用cglib动态代理加载模板类DigestCipher，并用DigestEnum枚举值重写模板类的getName
 * 实现每次计算hash值时，指定hash算法，以获取新的java.security.MessageDigest
 * 不使用JDK动态代理的原因是它是基于接口的，这里只需要代理getName()方法即可
 *
 * @author liuguanliang
 */
public final class Digest {
    private static final Map<String, AbstractDigest> DigestCipherMap = new HashMap<>(10);

    private Digest() {}

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    /**
     * 通过cglib用枚举值获取摘要算法代理对象
     */
    private static AbstractDigest getDigestProxy(DigestEnum digestEnum) {
        DigestMethodInterceptor digestMethodInterceptor = new DigestMethodInterceptor(digestEnum);

        Enhancer enhancer = new Enhancer();
        enhancer.setSuperclass(AbstractDigest.class);
        enhancer.setCallback(digestMethodInterceptor);

        AbstractDigest digestProxy = (AbstractDigest) enhancer.create();
        DigestCipherMap.put(digestEnum.getDesc(), digestProxy);

        return digestProxy;
    }

    /**
     * 指定由DigestEnum提供的摘要算法
     *
     * @param digestEnum 摘要算法枚举
     * @return DigestCipher 摘要计算对象代理
     */
    public static AbstractDigest use(DigestEnum digestEnum) {
        AbstractDigest digestProxy = DigestCipherMap.get(digestEnum.getDesc());
        if (null == digestProxy) {
            return getDigestProxy(digestEnum);
        }

        return digestProxy;
    }
}
