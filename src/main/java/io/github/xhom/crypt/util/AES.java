package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.SymCrypt;
import io.github.xhom.crypt.enums.CryptType;

/**
 * AES (Advanced Encryption Standard)
 * 对称加密
 * 是目前最流行的对称加密算法之一，支持128、192和256位的密钥长度
 * @author xhom
 * @version 2.0.0
 */
public class AES extends SymCrypt {
    /**
     * 生成密钥（128位）
     * @return 密钥
     */
    public static String generateKey() {
        return generateKey(128);
    }

    /**
     * 生成密钥
     * @param size 密钥长度（支持128、192和256位）
     * @return 密钥
     */
    public static String generateKey(int size) {
        return generateKey(CryptType.AES, size);
    }

    /**
     * 加密
     * @param data 数据
     * @param key 密钥
     * @return 加密结果
     */
    public static String encrypt(String data, String key) {
        return encrypt(data, key, CryptType.AES);
    }

    /**
     * 解密
     * @param data 已加密数据
     * @param key 密钥
     * @return 解密结果
     */
    public static String decrypt(String data, String key) {
        return decrypt(data, key, CryptType.AES);
    }
}
