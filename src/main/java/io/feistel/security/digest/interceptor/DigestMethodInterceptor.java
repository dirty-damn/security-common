package io.feistel.security.digest.interceptor;

import java.lang.reflect.Method;

import net.sf.cglib.proxy.MethodInterceptor;
import net.sf.cglib.proxy.MethodProxy;
import io.feistel.security.digest.DigestEnum;

/**
 * cglib动态代理的方法拦截对象
 * 代理DigestCipher对象的getName()方法，返回指定的摘要算法
 *
 * @author liuguanliang
 */
public class DigestMethodInterceptor implements MethodInterceptor {
    private DigestEnum digestEnum;

    public DigestMethodInterceptor(DigestEnum digestEnum) {
        this.digestEnum = digestEnum;
    }

    @Override
    public Object intercept(Object o, Method method, Object[] objects, MethodProxy methodProxy) throws Throwable {

        if ("getName".equals(method.getName())) {
            return digestEnum.getDesc();
        }

        return methodProxy.invokeSuper(o, objects);
    }
}
