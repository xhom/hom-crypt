package io.github.xhom.crypt.util;

import io.github.xhom.crypt.comm.CryptException;
import io.github.xhom.crypt.comm.StrKeyPair;
import io.github.xhom.crypt.core.AsymCrypt;
import io.github.xhom.crypt.enums.CryptType;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * DH (Diffie-Hellman)
 * 非对称加密
 * 用于密钥交换，不直接用于加密和解密
 * 是一种确保共享KEY安全穿越不安全网络的方法，也就是常说的密钥一致协议
 * 由公开密钥密码体制的奠基人Diffie和Hellman所提出的一种思想
 * 简单的说就是允许两名用户在公开媒体上交换信息以生成“一致”的、可以共享的密钥
 * 也就是由甲方产出一对密钥（公钥、私钥），乙方依照甲方公钥产生乙方密钥对（公钥、私钥）
 * DH算法的通信模型：
 *   1.甲方将自己的公钥发给乙方
 *   2.乙方根据甲方发来的公钥，生成自己的公钥和私钥
 *   3.乙方将自己的公钥发送给甲方
 *   4.甲方和乙方，生成一样的秘钥。用于加密数据
 * @author xhom
 * @version 2.0.0
 */
public class DH extends AsymCrypt {
    static {
        //开启JDK支持
        System.getProperties().setProperty("jdk.crypto.KeyAgreement.legacyKDF", "true");
    }

    /**
     * 甲方初始化一对密钥（512位）
     * @return 密钥对
     */
    public static StrKeyPair initKeyPair() {
        return initKeyPair(512);
    }

    /**
     * 甲方初始化一对密钥
     * @param size 密钥长度
     * @return 密钥对
     */
    public static StrKeyPair initKeyPair(int size) {
        return generateKeyPair(CryptType.DH, size);
    }

    /**
     * 乙方根据甲方公钥初始化一对密钥
     * @param publicKey 公钥
     * @return 密钥对
     */
    public static StrKeyPair initKeyPair(String publicKey) {
        try{
            PublicKey pubKey = StrKeyPair.toPublicKey(publicKey, CryptType.DH);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptType.DH.getAlgorithm());
            generator.initialize(((DHPublicKey)pubKey).getParams());
            KeyPair keyPair = generator.generateKeyPair();
            return StrKeyPair.of(keyPair);
        }catch (Exception e){
            throw CryptException.of("DH PublicKey生成密钥对异常", e);
        }
    }

    /**
     * 根据对方的公钥和自己的私钥生成本地密钥
     * @param publicKey 公钥
     * @param privateKey 私钥
     * @param cryptType 加密类型
     * @return 本地密钥
     */
    private static SecretKey getSecretKey(String publicKey, String privateKey, CryptType cryptType) {
        try {
            if(CryptType.DH.equals(cryptType)){
                throw CryptException.of("DH生成本地密钥不能使用相同算法");
            }
            PublicKey pubKey = StrKeyPair.toPublicKey(publicKey, CryptType.DH);
            PrivateKey priKey = StrKeyPair.toPrivateKey(privateKey, CryptType.DH);
            KeyAgreement agreement = KeyAgreement.getInstance(CryptType.DH.getAlgorithm());
            agreement.init(priKey);
            agreement.doPhase(pubKey, true);
            return agreement.generateSecret(cryptType.getAlgorithm());
        } catch (Exception e) {
            e.printStackTrace();
            throw CryptException.of("DH生成本地密钥异常", e);
        }
    }

    /**
     * 获得密钥（真正加密数据用的对称加密密钥）
     * @param publicKey 对方的公钥
     * @param privateKey 自己的私钥
     * @param cryptType 加密类型
     * @return 本地密钥
     */
    public static String getKey(String publicKey, String privateKey, CryptType cryptType){
        SecretKey secretKey = getSecretKey(publicKey, privateKey, cryptType);
        return BASE64.encodeToStr(secretKey.getEncoded());
    }

    /**
     * 加密
     * @param data 明文
     * @param publicKey 甲方公钥
     * @param privateKey 乙方私钥
     * @param cryptType 加密类型
     * @return 密文
     */
    public static String encrypt(String data, String publicKey, String privateKey, CryptType cryptType) {
        try {
            SecretKey secretKey = getSecretKey(publicKey, privateKey, cryptType);
            Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] bytes = cipher.doFinal(StrUtil.strToBytes(data));
            return BASE64.encodeToStr(bytes);
        } catch (Exception e) {
            throw CryptException.of("DH加密异常", e);
        }
    }

    /**
     * 解密
     * @param data 密文
     * @param publicKey 乙方公钥
     * @param privateKey 甲方私钥
     * @param cryptType 加密类型
     * @return 明文
     */
    public static String decrypt(String data, String publicKey, String privateKey, CryptType cryptType) {
        try {
            SecretKey secretKey = getSecretKey(publicKey, privateKey, cryptType);
            Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] bytes = cipher.doFinal(BASE64.decodeToBytes(data));
            return StrUtil.bytesToStr(bytes);
        } catch (Exception e) {
            throw CryptException.of("DH解密异常", e);
        }
    }
}
