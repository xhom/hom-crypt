package io.github.xhom.crypt.enums;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.function.Function;

/**
 * 加密类型枚举
 * @author xhom
 * @version 1.0.0
 */
public enum CryptType {
    AES("AES", "AES/ECB/PKCS5Padding", CryptType::getAESKeySpec),
    AES_CBC("AES", "AES/CBC/PKCS5Padding", CryptType::getAESKeySpec),
    DES("DES", "DES/ECB/PKCS5Padding", CryptType::getDESKeySpec),
    DES_CBC("DES", "DES/CBC/PKCS5Padding", CryptType::getDESKeySpec),
    DES3("DESede", "DESede", CryptType::getDESedeKeySpec),
    RC4("RC4", "RC4", CryptType::getRC4KeySpec),
    RSA("RSA", "RSA", null),
    DSA("DSA", "SHA256withDSA", null),
    DH("DH", "DH", null),
    MD5("MD5", null, null),
    SHA1("SHA-1", null, null),
    SHA256("SHA-256", null, null),
    SHA512("SHA-512", null, null),
    HMAC_MD5("HmacMD5", null, null),
    HMAC_SHA1("HmacSHA1", null, null),
    HMAC_SHA256("HmacSHA256", null, null),
    HMAC_SHA512("HmacSHA512", null, null);

    private final String algorithm;
    private final String cipher;
    private final Function<byte[], SecretKey> keyCreator;

    CryptType(String algorithm, String cipher, Function<byte[], SecretKey> keyCreator) {
        this.algorithm = algorithm;
        this.cipher = cipher;
        this.keyCreator = keyCreator;
    }

    public SecretKey getSecretKey(byte[] key){
        return keyCreator==null ? null : keyCreator.apply(key);
    }
    private SecretKey getSecretKey(KeySpec keySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(getAlgorithm());
        return keyFactory.generateSecret(keySpec);
    }
    private static SecretKey getAESKeySpec(byte[] key){
        return new SecretKeySpec(key, AES.getAlgorithm());
    }
    private static SecretKey getRC4KeySpec(byte[] key){
        return new SecretKeySpec(key, RC4.getAlgorithm());
    }
    private static SecretKey getDESKeySpec(byte[] key){
        try {
            return DES.getSecretKey(new DESKeySpec(key));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private static SecretKey getDESedeKeySpec(byte[] key){
        try {
            return DES3.getSecretKey(new DESedeKeySpec(key));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getCipher() {
        return cipher;
    }
}
