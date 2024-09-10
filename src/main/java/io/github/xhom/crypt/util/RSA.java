package io.github.xhom.crypt.util;

import io.github.xhom.crypt.comm.StrKeyPair;
import io.github.xhom.crypt.core.AsymCrypt;
import io.github.xhom.crypt.enums.CryptType;

/**
 * RSA (Rivest, Shamir, Adleman)
 * 非对称加密
 * 基于大数分解的困难性，经历了各种攻击但未被完全攻破
 * @author xhom
 * @version 2.0.0
 */
public class RSA extends AsymCrypt {
    /**
     * 生成密钥对（512位）
     * @return 密钥对
     */
    public static StrKeyPair generateKeyPair() {
        return generateKeyPair( 512);
    }

    /**
     * 生成密钥对
     * @param size 密钥长度（可取值512、1024、2048和4096，最小512）
     * @return 密钥对
     */
    public static StrKeyPair generateKeyPair(int size) {
        //密匙长度通常为1024或2048
        return generateKeyPair(CryptType.RSA, size);
    }

    /**
     * 加密
     * @param data 数据
     * @param publicKey 公钥
     * @return 加密结果
     */
    public static String encrypt(String data, String publicKey) {
        return encrypt(data, publicKey, CryptType.RSA);
    }

    /**
     * 解密
     * @param data 已加密数据
     * @param privateKey 私钥
     * @return 解密结果
     */
    public static String decrypt(String data, String privateKey) {
        return decrypt(data, privateKey, CryptType.RSA);
    }
}
