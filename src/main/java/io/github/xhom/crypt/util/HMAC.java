package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.enums.CryptType;

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
     * 计算校验码 (MD5)
     * @param data 数据
     * @param pass 密码
     * @return 校验码
     */
    public static String md5(String data, String pass) {
        return hmac(data, pass, CryptType.HMAC_MD5);
    }
    /**
     * 计算校验码 (SHA1)
     * @param data 数据
     * @param pass 密码
     * @return 校验码
     */
    public static String sha1(String data, String pass) {
        return hmac(data, pass, CryptType.HMAC_SHA1);
    }
    /**
     * 计算校验码 (SHA256)
     * @param data 数据
     * @param pass 密码
     * @return 校验码
     */
    public static String sha256(String data, String pass) {
        return hmac(data, pass, CryptType.HMAC_SHA256);
    }
    /**
     * 计算校验码 (SHA512)
     * @param data 数据
     * @param pass 密码
     * @return 校验码
     */
    public static String sha512(String data, String pass) {
        return hmac(data, pass, CryptType.HMAC_SHA512);
    }
}
