package io.github.xhom.crypt.comm;

import io.github.xhom.crypt.util.BASE64;
import lombok.Builder;
import lombok.Data;

import java.security.KeyPair;

/**
 * 密钥对（字符串）
 * @author xhom
 * @version 1.0.0
 */
@Data
@Builder
public class StrKeyPair {
    /**
     * 公钥
     */
    private String publicKey;
    /**
     * 私钥
     */
    private String privateKey;
    /**
     * 密钥对转换
     * @param keyPair 密钥对
     * @return 字符串密钥对
     */
    public static StrKeyPair of(KeyPair keyPair){
        String publicKey = BASE64.encodeToStr(keyPair.getPublic().getEncoded());
        String privateKey = BASE64.encodeToStr(keyPair.getPrivate().getEncoded());
        return StrKeyPair.builder().publicKey(publicKey).privateKey(privateKey).build();
    }
}
