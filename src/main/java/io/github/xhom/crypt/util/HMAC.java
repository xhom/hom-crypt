package io.github.xhom.crypt.util;

import io.github.xhom.crypt.comm.CryptException;
import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.enums.CryptType;

import javax.crypto.Mac;

/**
 * HMAC(Hash Message Authentication Code)
 * 散列消息鉴别码，基于密钥的Hash算法的认证协议
 * 消息鉴别码实现鉴别的原理是用公开函数和密钥产生一个固定长度的值作为认证标识，用这个标识鉴别消息的完整性
 * 使用一个密钥生成一个固定大小的小数据块，即MAC，并将其加入到消息中，然后传输，接收方利用与发送方共享的密钥进行鉴别认证等
 * 算法可以与许多哈希函数结合使用，常用的哈希函数包括：
 * HMAC-MD5：使用MD5哈希函数生成HMAC
 * HMAC-SHA1：使用SHA-1哈希函数生成HMAC
 * HMAC-SHA256：使用SHA-256哈希函数生成HMAC
 * HMAC-SHA512：使用SHA-512哈希函数生成HMAC
 * @author xhom
 * @version 2.0.0
 */
public class HMAC extends HashAlg {
    /**
     * 计算Hash值
     * @param data 数据
     * @param key 密码
     * @return hash值
     */
    public static String hash(String data, String key) {
        try{
            String algorithm = CryptType.HMAC.getAlgorithm();
            Mac mac = Mac.getInstance(algorithm);
            mac.init(CryptType.HMAC.getSecretKey(StrUtil.strToBytes(key)));
            byte[] bytes = mac.doFinal(StrUtil.strToBytes(data));
            return toHexString(bytes);
        }catch (Exception e) {
            throw CryptException.of("HMC计算异常", e);
        }
    }
}
