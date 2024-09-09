package io.github.xhom.crypt.core;

import io.github.xhom.crypt.comm.CryptException;
import io.github.xhom.crypt.enums.CryptType;
import io.github.xhom.crypt.util.StrUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 哈希算法通用类
 * @author visy.wang
 * @date 2024/9/9 15:32
 */
public class HashAlg {
    /**
     * 十六进制符号
     */
    private static final char[] HEX_CHARS = new char[] {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * 哈希计算
     * @param data 数据
     * @param cryptType 算法类型
     * @return 计算结果
     */
    public static String digest(String data, CryptType cryptType){
        String algorithm = cryptType.getAlgorithm();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] digest =  messageDigest.digest(StrUtil.strToBytes(data));
            return toHexString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw CryptException.of(algorithm+"计算异常", e);
        }
    }

    /**
     * 转十六进制字符串
     * @param bytes 二进制结果
     * @return 字符串
     */
    public static String toHexString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(HEX_CHARS[b >>> 4 & 15]);
            result.append(HEX_CHARS[b & 15]);
        }
        return result.toString();
    }
}
