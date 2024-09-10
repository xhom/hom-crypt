package io.github.xhom.crypt.util;

import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.enums.CryptType;

/**
 * MD5 (Message Digest Algorithm 5)
 * 是一种广泛使用的哈希算法，生成的哈希值为 128 位（16 字节）
 * 常用于校验数据的完整性，但由于其存在安全性漏洞，已不适合用于密码存储等安全场景
 * @author xhom
 * @version 2.0.0
 */
public class MD5 extends HashAlg {
    /**
     * 计算Hash值
     * @param data 数据
     * @return md5值
     */
    public static String hash(String data) {
        return digest(data, CryptType.MD5);
    }

    /**
     * 验证哈希值
     * @param data 数据
     * @param md5 md5哈希值
     * @return 是否验证成功
     */
    public static boolean verify(String data, String md5) {
        return StrUtil.equalsNoEarlyReturn(md5, hash(data));
    }
}
