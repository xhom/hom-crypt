package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.SymCrypt;
import io.github.xhom.crypt.enums.CryptType;

/**
 * 3DES (Triple DES)
 * 对称加密
 * 是DES的改进版，使用168位的密钥进行加密
 * @author xhom
 * @version 2.0.0
 */
public class DES3 extends SymCrypt {
    /**
     * 生成密钥（168位）
     * @return 密钥
     */
    public static String generateKey() {
        return generateKey(168);
    }

    /**
     * 生成密钥
     * @param size 密钥长度
     * @return 密钥
     */
    public static String generateKey(int size) {
        return generateKey(CryptType.DES3, size);
    }

    /**
     * 加密
     * @param data 数据
     * @param key 密钥
     * @return 加密结果
     */
    public static String encrypt(String data, String key) {
        return encrypt(data, key, CryptType.DES3);
    }

    /**
     * 解密
     * @param data 已加密数据
     * @param key 密钥
     * @return 解密结果
     */
    public static String decrypt(String data, String key) {
        return decrypt(data, key, CryptType.DES3);
    }
}
