package io.github.xhom.crypt.util;

import java.nio.charset.StandardCharsets;

/**
 * 字符串工具类
 * @author visy.wang
 * @date 2024/9/9 15:17
 */
public class StrUtil {
    /**
     * 更安全的字符串比对（可防止时间序列攻击）
     * 来自org.springframework.security.crypto.bcrypt.BCrypt
     * @param a 字符串a
     * @param b 字符串b
     * @return 是否相同
     */
    public static boolean equalsNoEarlyReturn(String a, String b) {
        char[] caa = a.toCharArray(), cab = b.toCharArray();
        if (caa.length != cab.length) {
            return false;
        }
        byte ret = 0;
        for(int i = 0; i < caa.length; ++i) {
            ret = (byte)(ret | caa[i] ^ cab[i]);
        }
        return ret == 0;
    }

    /**
     * 字符串转byte数组
     * @param str 字符串
     * @return byte数组
     */
    public static byte[] strToBytes(String str){
        return str.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * byte数组转字符串
     * @param bytes byte数组
     * @return 字符串
     */
    public static String bytesToStr(byte[] bytes){
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
