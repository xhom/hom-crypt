package io.github.xhom.crypt.util;

import io.github.xhom.crypt.comm.StrKeyPair;
import io.github.xhom.crypt.core.AsymCrypt;
import io.github.xhom.crypt.enums.CryptType;

/**
 * DSA (Digital Signature Algorithm)
 * 非对称加密
 * 用于数字签名，确保信息的完整性和来源的真实性
 * @author xhom
 * @version 2.0.0
 */
public class DSA extends AsymCrypt {
    /**
     * 生成密钥对（1024位）
     * @return 密钥对
     */
    public static StrKeyPair generateKeyPair() {
        return generateKeyPair(1024);
    }

    /**
     * 生成密钥对
     * @param size 密钥长度
     * @return 密钥对
     */
    public static StrKeyPair generateKeyPair(int size) {
        return generateKeyPair(CryptType.DSA, 1024);
    }

    /**
     * 签名
     * @param data 数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, String privateKey) {
        return sign(data, privateKey, CryptType.DSA);
    }

    /**
     * 验签
     * @param data 数据（未加密）
     * @param publicKey 公钥
     * @param sign 签名
     * @return 是否验证通过
     */
    public static boolean verify(String data, String publicKey, String sign) {
        return verify(data, publicKey, sign, CryptType.DSA);
    }
}
