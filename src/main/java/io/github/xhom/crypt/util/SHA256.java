package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.enums.CryptType;

/**
 * SHA-256 (Secure Hash Algorithm 256-bit)
 * SHA-256 是 SHA-2 系列中的一种哈希算法，生成的哈希值长度为 256 位（32 字节）
 * 具有更高的安全性，SHA-256 在许多领域中被广泛使用，包括密码学、数字证书等
 * @author xhom
 * @version 2.0.0
 */
public class SHA256 extends HashAlg {
    /**
     * 计算Hash值
     * @param data 数据
     * @return sha256值
     */
    public static String hash(String data) {
        return digest(data, CryptType.SHA256);
    }

    /**
     * 验证哈希值
     * @param data 数据
     * @param sha256 sha256哈希值
     * @return 是否验证成功
     */
    public static boolean verify(String data, String sha256) {
        return StrUtil.equalsNoEarlyReturn(sha256, hash(data));
    }
}
