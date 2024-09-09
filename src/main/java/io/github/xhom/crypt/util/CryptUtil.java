package io.github.xhom.crypt.util;

import io.github.xhom.crypt.comm.CryptException;
import io.github.xhom.crypt.comm.StrKeyPair;
import io.github.xhom.crypt.core.AsymCrypt;
import io.github.xhom.crypt.core.HashAlg;
import io.github.xhom.crypt.core.SymCrypt;
import io.github.xhom.crypt.enums.CryptType;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 加密解密工具集（基于JDK）
 * @author xhom
 * @version 1.0.0
 */
public class CryptUtil {
    /**
     * AES (Advanced Encryption Standard)
     * 对称加密
     * 是目前最流行的对称加密算法之一，支持128、192和256位的密钥长度
     */
    public static class AES {
        /**
         * 生成密钥
         * @return 密钥
         */
        public static String generateKey() {
            return SymCrypt.generateKey(CryptType.AES, 128);
        }
        /**
         * 加密
         * @param data 数据
         * @param key 密钥
         * @return 加密结果
         */
        public static String encrypt(String data, String key) {
            return SymCrypt.encrypt(data, key, CryptType.AES);
        }
        /**
         * 解密
         * @param data 已加密数据
         * @param key 密钥
         * @return 解密结果
         */
        public static String decrypt(String data, String key) {
            return SymCrypt.decrypt(data, key, CryptType.AES);
        }
    }

    /**
     * DES (Data Encryption Standard)
     * 对称加密
     * 使用56位的密钥进行加密，已被证实可以在短时间内破解
     */
    public static class DES {
        /**
         * 生成密钥
         * @return 密钥
         */
        public static String generateKey() {
            return SymCrypt.generateKey(CryptType.DES, 56);
        }
        /**
         * 加密
         * @param data 数据
         * @param key 密钥
         * @return 加密结果
         */
        public static String encrypt(String data, String key) {
            return SymCrypt.encrypt(data, key, CryptType.DES);
        }
        /**
         * 解密
         * @param data 已加密数据
         * @param key 密钥
         * @return 解密结果
         */
        public static String decrypt(String data, String key) {
            return SymCrypt.decrypt(data, key, CryptType.DES);
        }
    }

    /**
     * 3DES (Triple DES)
     * 对称加密
     * 是DES的改进版，使用168位的密钥进行加密
     */
    public static class DES3 {
        /**
         * 生成密钥
         * @return 密钥
         */
        public static String generateKey() {
            return SymCrypt.generateKey(CryptType.DES3, 168);
        }
        /**
         * 加密
         * @param data 数据
         * @param key 密钥
         * @return 加密结果
         */
        public static String encrypt(String data, String key) {
            return SymCrypt.encrypt(data, key, CryptType.DES3);
        }
        /**
         * 解密
         * @param data 已加密数据
         * @param key 密钥
         * @return 解密结果
         */
        public static String decrypt(String data, String key) {
            return SymCrypt.decrypt(data, key, CryptType.DES3);
        }
    }

    /**
     * RC4 (Rivest Cipher 4)
     * 对称加密
     * 速度较快，但安全性较低，已被认为不够安全。
     */
    public static class RC4 {
        /**
         * 生成密钥
         * @return 密钥
         */
        public static String generateKey() {
            return SymCrypt.generateKey(CryptType.RC4);
        }
        /**
         * 加密
         * @param data 数据
         * @param key 密钥
         * @return 加密结果
         */
        public static String encrypt(String data, String key) {
            return SymCrypt.encrypt(data, key, CryptType.RC4);
        }
        /**
         * 解密
         * @param data 已加密数据
         * @param key 密钥
         * @return 解密结果
         */
        public static String decrypt(String data, String key) {
            return SymCrypt.decrypt(data, key, CryptType.RC4);
        }
    }

    /*
     * SM4 (国密)
     * 对称加密
     * 由我国国家密码管理局发布，常用于无线互联网加密等领域
     */

    /**
     * RSA (Rivest, Shamir, Adleman)
     * 非对称加密
     * 基于大数分解的困难性，经历了各种攻击但未被完全攻破
     */
    public static class RSA {
        /**
         * 生成密钥对
         * @return 密钥对
         */
        public static StrKeyPair generateKeyPair() {
            //密匙长度通常为1024或2048
            //可取值512、1024、2048和4096，最小512
            return AsymCrypt.generateKeyPair(CryptType.RSA, 512);
        }
        /**
         * 加密
         * @param data 数据
         * @param publicKey 公钥
         * @return 加密结果
         */
        public static String encrypt(String data, String publicKey) {
            return AsymCrypt.encrypt(data, publicKey, CryptType.RSA);
        }
        /**
         * 解密
         * @param data 已加密数据
         * @param privateKey 私钥
         * @return 解密结果
         */
        public static String decrypt(String data, String privateKey) {
            return AsymCrypt.decrypt(data, privateKey, CryptType.RSA);
        }
    }

    /*
     * ECC (Elliptic Curve Cryptography)
     * 非对称加密
     * 使用椭圆曲线数学进行加密，安全性较高
     */

    /**
     * DSA (Digital Signature Algorithm)
     * 非对称加密
     * 用于数字签名，确保信息的完整性和来源的真实性
     */
    public static class DSA {
        /**
         * 生成密钥对
         * @return 密钥对
         */
        public static StrKeyPair generateKeyPair() {
            return AsymCrypt.generateKeyPair(CryptType.DSA, 1024);
        }
        /**
         * 签名
         * @param data 数据
         * @param privateKey 私钥
         * @return 加密结果
         */
        public static String sign(String data, String privateKey) {
            return AsymCrypt.sign(data, privateKey, CryptType.DSA);
        }
        /**
         * 验签
         * @param data 数据（未加密）
         * @param publicKey 公钥
         * @param sign 签名
         * @return 是否验证通过
         */
        public static boolean verify(String data, String publicKey, String sign) {
            return AsymCrypt.verify(data, publicKey, sign, CryptType.DSA);
        }
    }

    /*
     * SM2 (国密)
     * 非对称加密
     * 中国的国家密码标准，类似于RSA。‌
     */

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
     */
    public static class DH {
        static {
            System.getProperties().setProperty("jdk.crypto.KeyAgreement.legacyKDF", "true");
        }
        /**
         * 甲方初始化一对密钥
         * @return 密钥对
         */
        public static StrKeyPair initKeyPair() {
            return AsymCrypt.generateKeyPair(CryptType.DH, 512);
        }
        /**
         * 乙方根据甲方公钥初始化一对密钥
         * @param pubKey 公钥
         * @return 密钥对
         */
        public static StrKeyPair initKeyPair(String pubKey) {
            String algorithm = CryptType.DH.getAlgorithm();
            try {
                //读取公钥信息
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(BASE64.decodeToBytes(pubKey));
                DHPublicKey publicKey = (DHPublicKey) keyFactory.generatePublic(keySpec);
                //根据公钥生成一对新的密钥
                KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
                generator.initialize(publicKey.getParams());
                KeyPair keyPair = generator.generateKeyPair();
                return StrKeyPair.of(keyPair);
            } catch (Exception e) {
                throw CryptException.of(algorithm+"pubKey生成密匙对异常", e);
            }
        }
        /**
         * 根据对方的公钥和自己的私钥生成本地密钥
         * @param pubKey 公钥
         * @param priKey 私钥
         * @param cryptType 加密类型
         * @return 本地密钥
         */
        private static SecretKey getSecretKey(String pubKey, String priKey, CryptType cryptType) {
            try {
                String algorithm = CryptType.DH.getAlgorithm();
                if(CryptType.DH.equals(cryptType)){
                    throw CryptException.of("DH生成本地密钥不能使用相同算法");
                }
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(BASE64.decodeToBytes(pubKey));
                PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(BASE64.decodeToBytes(priKey));
                PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
                PrivateKey privateKey = keyFactory.generatePrivate(priKeySpec);
                KeyAgreement agreement = KeyAgreement.getInstance(algorithm);
                agreement.init(privateKey);
                agreement.doPhase(publicKey, true);
                return agreement.generateSecret(cryptType.getAlgorithm());
            } catch (Exception e) {
                throw CryptException.of("DH生成本地密钥异常", e);
            }
        }
        /**
         * 获得AES密钥
         * @param pubKey 对方的公钥
         * @param priKey 自己的私钥
         * @param cryptType 加密类型
         * @return AES密钥
         */
        public static String getKey(String pubKey, String priKey, CryptType cryptType){
            SecretKey secretKey = getSecretKey(pubKey, priKey, cryptType);
            return BASE64.encodeToStr(secretKey.getEncoded());
        }
        /**
         * 加密
         * @param data 明文
         * @param pubKey 甲方公钥
         * @param priKey 乙方私钥
         * @param cryptType 加密类型
         * @return 密文
         */
        public static String encrypt(String data, String pubKey, String priKey, CryptType cryptType) {
            try {
                SecretKey secretKey = getSecretKey(pubKey, priKey, cryptType);
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
         * @param pubKey 乙方公钥
         * @param priKey 甲方私钥
         * @param cryptType 加密类型
         * @return 明文
         */
        public static String decrypt(String data, String pubKey, String priKey, CryptType cryptType) {
            try {
                SecretKey secretKey = getSecretKey(pubKey, priKey, cryptType);
                Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] bytes = cipher.doFinal(BASE64.decodeToBytes(data));
                return StrUtil.bytesToStr(bytes);
            } catch (Exception e) {
                throw CryptException.of("DH解密异常", e);
            }
        }
    }

    /**
     * MD5 (Message Digest Algorithm 5)
     * 是一种广泛使用的哈希算法，生成的哈希值为 128 位（16 字节）
     * 常用于校验数据的完整性，但由于其存在安全性漏洞，已不适合用于密码存储等安全场景
     */
    public static class MD5 {
        /**
         * 计算Hash值
         * @param data 数据
         * @return hash值
         */
        public static String hash(String data) {
            return HashAlg.digest(data, CryptType.MD5);
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

    /**
     * SHA-1 (Secure Hash Algorithm 1)
     * SHA-1 是一种产生 160 位（20 字节）哈希值的算法
     * 然而，SHA-1也被证明存在安全性问题，因此在对数据的完整性和安全性要求较高的场景中，不再推荐使用
     */
    public static class SHA1 {
        /**
         * 计算Hash值
         * @param data 数据
         * @return hash值
         */
        public static String hash(String data) {
            return HashAlg.digest(data, CryptType.SHA1);
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

    /**
     * SHA-256 (Secure Hash Algorithm 256-bit)
     * SHA-256 是 SHA-2 系列中的一种哈希算法，生成的哈希值长度为 256 位（32 字节）
     * 具有更高的安全性，SHA-256 在许多领域中被广泛使用，包括密码学、数字证书等
     */
    public static class SHA256 {
        /**
         * 计算Hash值
         * @param data 数据
         * @return hash值
         */
        public static String hash(String data) {
            return HashAlg.digest(data, CryptType.SHA256);
        }
        /**
         * 验证哈希值
         * @param data 数据
         * @param sha256 sha256哈希值
         * @return 是否验证成功
         */
        public static boolean verify(String data, String sha256) {
            return StrUtil.equalsNoEarlyReturn(sha256, hash(data));
        }
    }

    /**
     * SHA-512 (Secure Hash Algorithm 512-bit)
     */
    public static class SHA512 {
        /**
         * 计算Hash值
         * @param data 数据
         * @return hash值
         */
        public static String hash(String data) {
            return HashAlg.digest(data, CryptType.SHA512);
        }
        /**
         * 验证哈希值
         * @param data 数据
         * @param sha512 sha512哈希值
         * @return 是否验证成功
         */
        public static boolean verify(String data, String sha512) {
            return StrUtil.equalsNoEarlyReturn(sha512, hash(data));
        }
    }

    /**
     * HMAC(Hash Message Authentication Code)
     * 散列消息鉴别码，基于密钥的Hash算法的认证协议
     * 消息鉴别码实现鉴别的原理是用公开函数和密钥产生一个固定长度的值作为认证标识，用这个标识鉴别消息的完整性
     * 使用一个密钥生成一个固定大小的小数据块，即MAC，并将其加入到消息中，然后传输，接收方利用与发送方共享的密钥进行鉴别认证等
     * 算法可以与许多哈希函数结合使用，常用的哈希函数包括：
     * HMAC-MD5：使用MD5哈希函数生成HMAC
     * HMAC-SHA1：使用SHA-1哈希函数生成HMAC
     * HMAC-SHA256：使用SHA-256哈希函数生成HMAC
     * HMAC-SHA512：使用SHA-512哈希函数生成HMAC
     */
    public static class HMAC {
        /**
         * 计算Hash值
         * @param data 数据
         * @param key 密码
         * @return hash值
         */
        public static String hash(String data, String key) {
            try{
                String algorithm = CryptType.HMAC.getAlgorithm();
                Mac mac = Mac.getInstance(algorithm);
                mac.init(CryptType.HMAC.getSecretKey(StrUtil.strToBytes(key)));
                byte[] bytes = mac.doFinal(StrUtil.strToBytes(data));
                return HashAlg.toHexString(bytes);
            }catch (Exception e) {
                throw CryptException.of("HMC计算异常", e);
            }
        }
    }
}
