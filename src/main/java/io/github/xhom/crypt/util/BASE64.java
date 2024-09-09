package io.github.xhom.crypt.util;

import java.util.Base64;

/**
 * BASE64编码工具
 * 网络上最常见的用于传输8Bit字节码的编码方式之一，就是一种基于64个可打印字符来表示二进制数据的方法
 * 包括小写字母a-z、大写字母A-Z、数字0-9、符号"+"、"/"一共64个字符的字符集
 * 任何符号都可以转换成这个字符集中的字符，这个转换过程就叫做base64编码
 * @author visy.wang
 * @date 2024/9/9 15:25
 */
public class BASE64 {
    public static Base64.Encoder encoder = Base64.getEncoder();
    public static Base64.Decoder decoder = Base64.getDecoder();
    //对URL的编码方式，替换“+” “/” 为“-” “_”
    public static Base64.Encoder urlEncoder = Base64.getUrlEncoder();
    public static Base64.Decoder urlDecoder = Base64.getUrlDecoder();

    public static byte[] encode(byte[] data) {
        return encoder.encode(data);
    }
    public static String encodeToStr(byte[] data) {
        return StrUtil.bytesToStr(encode(data));
    }
    public static String encode(String data) {
        return encodeToStr(StrUtil.strToBytes(data));
    }
    public static byte[] encodeToBytes(String data) {
        return encode(StrUtil.strToBytes(data));
    }
    public static byte[] urlEncode(byte[] data) {
        return urlEncoder.encode(data);
    }
    public static String urlEncodeToStr(byte[] data) {
        return StrUtil.bytesToStr(urlEncode(data));
    }
    public static String urlEncode(String data) {
        return urlEncodeToStr(StrUtil.strToBytes(data));
    }
    public static byte[] urlEncodeToBytes(String data) {
        return urlEncode(StrUtil.strToBytes(data));
    }
    public static byte[] decode(byte[] data) {
        return decoder.decode(data);
    }
    public static String decodeToStr(byte[] data) {
        return StrUtil.bytesToStr(decode(data));
    }
    public static String decode(String data) {
        return decodeToStr(StrUtil.strToBytes(data));
    }
    public static byte[] decodeToBytes(String data) {
        return decode(StrUtil.strToBytes(data));
    }
    public static byte[] urlDecode(byte[] data) {
        return urlDecoder.decode(data);
    }
    public static String urlDecodeToStr(byte[] data) {
        return StrUtil.bytesToStr(urlDecode(data));
    }
    public static String urlDecode(String data) {
        return urlDecodeToStr(StrUtil.strToBytes(data));
    }
    public static byte[] urlDecodeToBytes(String data) {
        return urlDecode(StrUtil.strToBytes(data));
    }
}