package io.github.xhom.crypt.comm;

import io.github.xhom.crypt.enums.CryptType;
import io.github.xhom.crypt.util.BASE64;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 密钥对（字符串）
 * @author xhom
 * @version 1.0.0
 */
public class StrKeyPair {
    /**
     * 公钥
     */
    private String publicKey;
    /**
     * 私钥
     */
    private String privateKey;

    public StrKeyPair() {}

    public StrKeyPair(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * 密钥对转换
     * @param keyPair 密钥对
     * @return 字符串密钥对
     */
    public static StrKeyPair of(KeyPair keyPair){
        String publicKey = BASE64.encodeToStr(keyPair.getPublic().getEncoded());
        String privateKey = BASE64.encodeToStr(keyPair.getPrivate().getEncoded());
        return new StrKeyPair(publicKey, privateKey);
    }

    /**
     * 获取公钥
     * @return 公钥
     */
    public String getPublicKey() {
        return publicKey;
    }

    /**
     * 获取私钥
     * @return 私钥
     */
    public String getPrivateKey() {
        return privateKey;
    }

    /**
     * 转换成PublicKey
     * @param cryptType 加密类型
     * @return 公钥实例
     * @throws NoSuchAlgorithmException 查无此算法
     * @throws InvalidKeySpecException 无效的公钥
     */
    public PublicKey toPublicKey(CryptType cryptType) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return toPublicKey(getPublicKey(), cryptType);
    }

    /**
     * 转换成PrivateKey
     * @param cryptType 加密类型
     * @return 私钥实例
     * @throws NoSuchAlgorithmException 查无此算法
     * @throws InvalidKeySpecException 无效的私钥
     */
    public PrivateKey toPrivateKey(CryptType cryptType) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return toPrivateKey(getPrivateKey(), cryptType);
    }

    /**
     * 转换成PublicKey
     * @param publicKey 公钥
     * @param cryptType 加密类型
     * @return 公钥实例
     * @throws NoSuchAlgorithmException 查无此算法
     * @throws InvalidKeySpecException 无效的公钥
     */
    public static PublicKey toPublicKey(String publicKey, CryptType cryptType) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(cryptType.getAlgorithm());
        byte[] keyBytes = BASE64.decodeToBytes(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 转换成PrivateKey
     * @param privateKey 私钥
     * @param cryptType 加密类型
     * @return 私钥实例
     * @throws NoSuchAlgorithmException 查无此算法
     * @throws InvalidKeySpecException 无效的私钥
     */
    public static PrivateKey toPrivateKey(String privateKey, CryptType cryptType) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(cryptType.getAlgorithm());
        byte[] keyBytes = BASE64.decodeToBytes(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(keySpec);
    }
}
