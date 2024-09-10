package io.github.xhom.crypt.core;

import io.github.xhom.crypt.comm.CryptException;
import io.github.xhom.crypt.comm.StrKeyPair;
import io.github.xhom.crypt.enums.CryptType;
import io.github.xhom.crypt.util.BASE64;
import io.github.xhom.crypt.util.StrUtil;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * 非对称加密通用类
 * @author xhom
 * @version 1.0.0
 */
public class AsymCrypt {
    /**
     * 生成密钥对
     * @param cryptType 加密类型
     * @param size 密钥长度
     * @return 密钥对
     */
    public static StrKeyPair generateKeyPair(CryptType cryptType, Integer size){
        String algorithm = cryptType.getAlgorithm();
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(size, new SecureRandom());
            KeyPair keyPair = generator.generateKeyPair();
            return StrKeyPair.of(keyPair);
        }catch (NoSuchAlgorithmException e) {
            throw CryptException.of(algorithm+"生成密匙对异常", e);
        }
    }

    /**
     * 加密
     * @param data 明文
     * @param pubKey 公钥
     * @param cryptType 加密类型
     * @return 密文
     */
    public static String encrypt(String data, String pubKey, CryptType cryptType) {
        String algorithm = cryptType.getAlgorithm();
        try {
            byte[] plaintext = StrUtil.strToBytes(data);
            PublicKey publicKey = StrKeyPair.toPublicKey(pubKey, cryptType);
            Cipher cipher = Cipher.getInstance(cryptType.getCipher());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
            byte[] ciphertext = cipher.doFinal(plaintext);
            return BASE64.encodeToStr(ciphertext);
        } catch (Exception e) {
            throw CryptException.of(algorithm+"加密异常", e);
        }
    }

    /**
     * 解密
     * @param data 密文
     * @param prikey 私钥
     * @param cryptType 加密类型
     * @return 明文
     */
    public static String decrypt(String data, String prikey, CryptType cryptType) {
        String algorithm = cryptType.getAlgorithm();
        try {
            byte[] ciphertext = BASE64.decodeToBytes(data);
            PrivateKey privateKey = StrKeyPair.toPrivateKey(prikey, cryptType);
            Cipher decryptCipher = Cipher.getInstance(cryptType.getCipher());
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey, new SecureRandom());
            byte[] plaintext = decryptCipher.doFinal(ciphertext);
            return StrUtil.bytesToStr(plaintext);
        } catch (Exception e) {
            throw CryptException.of(algorithm+"解密异常", e);
        }
    }

    /**
     * 数字签名
     * @param data 数据
     * @param priKey 私钥
     * @param cryptType 加密类型
     * @return 签名
     */
    public static String sign(String data, String priKey, CryptType cryptType){
        String algorithm = cryptType.getAlgorithm();
        try {
            byte[] plaintext = BASE64.encodeToBytes(data);
            PrivateKey privateKey = StrKeyPair.toPrivateKey(priKey, cryptType);
            Signature signature = Signature.getInstance(cryptType.getCipher());
            signature.initSign(privateKey);
            signature.update(plaintext);
            byte[] sign = signature.sign();
            return BASE64.encodeToStr(sign);
        } catch (Exception e) {
            throw CryptException.of(algorithm+"签名异常", e);
        }
    }

    /**
     * 验签
     * @param data 数据
     * @param pubKey 公钥
     * @param sign 签名
     * @param cryptType 加密类型
     * @return 是否验证通过
     */
    public static boolean verify(String data, String pubKey, String sign, CryptType cryptType){
        String algorithm = cryptType.getAlgorithm();
        try {
            byte[] plaintext = BASE64.encodeToBytes(data);
            PublicKey publicKey = StrKeyPair.toPublicKey(pubKey, cryptType);
            Signature signature = Signature.getInstance(cryptType.getCipher());
            signature.initVerify(publicKey);
            signature.update(plaintext);
            return signature.verify(BASE64.decodeToBytes(sign));
        } catch (Exception e) {
            throw CryptException.of(algorithm+"验签异常", e);
        }
    }
}
