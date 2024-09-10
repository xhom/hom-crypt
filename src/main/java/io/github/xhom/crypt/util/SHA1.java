package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.enums.CryptType;

/**
 * SHA-1 (Secure Hash Algorithm 1)
 * SHA-1 是一种产生 160 位（20 字节）哈希值的算法
 * 然而，SHA-1也被证明存在安全性问题，因此在对数据的完整性和安全性要求较高的场景中，不再推荐使用
 * @author xhom
 * @version 2.0.0
 */
public class SHA1 extends HashAlg {
    /**
     * 计算Hash值
     * @param data 数据
     * @return sha1值
     */
    public static String hash(String data) {
        return digest(data, CryptType.SHA1);
    }

    /**
     * 验证哈希值
     * @param data 数据
     * @param sha1 sha1哈希值
     * @return 是否验证成功
     */
    public static boolean verify(String data, String sha1) {
        return StrUtil.equalsNoEarlyReturn(sha1, hash(data));
    }
}
