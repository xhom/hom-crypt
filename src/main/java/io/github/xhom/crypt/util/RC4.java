package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.SymCrypt;
import io.github.xhom.crypt.enums.CryptType;

/**
 * RC4 (Rivest Cipher 4)
 * 对称加密
 * 速度较快，但安全性较低，已被认为不够安全
 * @author xhom
 * @version 2.0.0
 */
public class RC4 extends SymCrypt {
    /**
     * 生成密钥
     * @return 密钥
     */
    public static String generateKey() {
        return generateKey(CryptType.RC4);
    }

    /**
     * 加密
     * @param data 数据
     * @param key 密钥
     * @return 加密结果
     */
    public static String encrypt(String data, String key) {
        return encrypt(data, key, CryptType.RC4);
    }

    /**
     * 解密
     * @param data 已加密数据
     * @param key 密钥
     * @return 解密结果
     */
    public static String decrypt(String data, String key) {
        return decrypt(data, key, CryptType.RC4);
    }

}
