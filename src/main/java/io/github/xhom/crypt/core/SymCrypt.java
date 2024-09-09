package io.github.xhom.crypt.core;

import io.github.xhom.crypt.comm.CryptException;
import io.github.xhom.crypt.enums.CryptType;
import io.github.xhom.crypt.util.BASE64;
import io.github.xhom.crypt.util.StrUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * 对称加密通用类
 * @author xhom
 * @version 1.0.0
 */
public class SymCrypt {
    /**
     * 初始化向量的长度
     */
    private static final int IV_LENGTH = 16;

    /**
     * 生成密匙
     * @param cryptType 加密类型
     * @return 密匙
     */
    public static String generateKey(CryptType cryptType) {
        return generateKey(cryptType, null);
    }

    /**
     * 生成密匙
     * @param cryptType 加密类型
     * @param size 密匙长度
     * @return 密匙
     */
    public static String generateKey(CryptType cryptType, Integer size) {
        String algorithm = cryptType.getAlgorithm();
        try {
            KeyGenerator generator = KeyGenerator.getInstance(algorithm);
            if(Objects.isNull(size)){
                generator.init(new SecureRandom());
            }else{
                generator.init(size, new SecureRandom());
            }
            byte[] key = generator.generateKey().getEncoded();
            return BASE64.encodeToStr(key);
        } catch (NoSuchAlgorithmException e) {
            throw CryptException.of(algorithm+"生成密匙异常", e);
        }
    }

    /**
     * 加密
     * @param data 明文
     * @param key 密匙
     * @param cryptType 加密类型
     * @return 密文
     */
    public static String encrypt(String data, String key, CryptType cryptType) {
        String algorithm = cryptType.getAlgorithm();
        try {
            SecureRandom sr = new SecureRandom();
            String cipherName = cryptType.getCipher();
            Cipher cipher = Cipher.getInstance(cipherName);
            byte[] plaintext = StrUtil.strToBytes(data);
            SecretKey secretKey = cryptType.getSecretKey(BASE64.decodeToBytes(key));
            if(cipherName.contains("/CBC/")){
                //CBC模式，需要生成一个16位的初始化向量，同一明文每次生成的密文不一样（类似于加盐）
                byte[] iv = sr.generateSeed(IV_LENGTH);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                byte[] ciphertext = cipher.doFinal(plaintext);
                //拼接iv和加密结果
                byte[] result = new byte[iv.length + ciphertext.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
                return BASE64.encodeToStr(result);
            }else{
                //ECB模式，不需要初始化向量，同一明文每次生成的密文一样
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, sr);
                byte[] ciphertext = cipher.doFinal(plaintext);
                return BASE64.encodeToStr(ciphertext);
            }
        } catch (Exception e) {
            throw CryptException.of(algorithm+"加密异常", e);
        }
    }

    /**
     * 解密
     * @param data 密文
     * @param key 密匙
     * @param cryptType 加密类型
     * @return 明文
     */
    public static String decrypt(String data, String key, CryptType cryptType) {
        String algorithm = cryptType.getAlgorithm();
        try {
            byte[] ciphertext;
            String cipherName = cryptType.getCipher();
            byte[] dataBytes = BASE64.decodeToBytes(data);
            Cipher cipher = Cipher.getInstance(cipherName);
            SecretKey secretKey = cryptType.getSecretKey(BASE64.decodeToBytes(key));
            if(cipherName.contains("/CBC/")){
                //CBC模式
                //把data分割成IV和密文
                byte[] iv = new byte[IV_LENGTH];
                ciphertext = new byte[dataBytes.length-IV_LENGTH];
                System.arraycopy(dataBytes, 0, iv, 0, IV_LENGTH);//复制IV
                System.arraycopy(dataBytes, IV_LENGTH, ciphertext, 0, ciphertext.length);//复制密文
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }else{
                //ECB模式
                ciphertext = dataBytes;
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new SecureRandom());
            }
            byte[] plaintext = cipher.doFinal(ciphertext);
            return StrUtil.bytesToStr(plaintext);
        } catch (Exception e) {
            throw CryptException.of(algorithm+"解密异常", e);
        }
    }
}