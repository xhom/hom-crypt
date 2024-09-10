package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.enums.CryptType;

/**
 * SHA-512 (Secure Hash Algorithm 512-bit)
 * @author xhom
 * @version 2.0.0
 */
public class SHA512 extends HashAlg {
    /**
     * 计算Hash值
     * @param data 数据
     * @return sha512值
     */
    public static String hash(String data) {
        return digest(data, CryptType.SHA512);
    }

    /**
     * 验证哈希值
     * @param data 数据
     * @param sha512 sha512哈希值
     * @return 是否验证成功
     */
    public static boolean verify(String data, String sha512) {
        return StrUtil.equalsNoEarlyReturn(sha512, hash(data));
    }
}
