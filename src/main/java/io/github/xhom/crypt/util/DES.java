package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.SymCrypt;
import io.github.xhom.crypt.enums.CryptType;

/**
 * DES (Data Encryption Standard)
 * 对称加密
 * 使用56位的密钥进行加密，已被证实可以在短时间内破解
 * @author xhom
 * @version 2.0.0
 */
public class DES extends SymCrypt {
    /**
     * 生成密钥（56位）
     * @return 密钥
     */
    public static String generateKey() {
        return generateKey(56);
    }

    /**
     * 生成密钥
     * @param size 密钥长度
     * @return 密钥
     */
    public static String generateKey(int size) {
        return generateKey(CryptType.DES, size);
    }

    /**
     * 加密
     * @param data 数据
     * @param key 密钥
     * @return 加密结果
     */
    public static String encrypt(String data, String key) {
        return encrypt(data, key, CryptType.DES);
    }

    /**
     * 解密
     * @param data 已加密数据
     * @param key 密钥
     * @return 解密结果
     */
    public static String decrypt(String data, String key) {
        return decrypt(data, key, CryptType.DES);
    }
}
