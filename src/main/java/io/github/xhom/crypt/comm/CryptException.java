package io.github.xhom.crypt.comm;

/**
 * 加密业务异常
 * @author xhom
 * @version 1.0.0
 */
public class CryptException extends RuntimeException {
    public CryptException(String message) {
        super(message);
    }
    public CryptException(String message, Throwable cause) {
        super(message, cause);
    }
    public static CryptException of(String prefix, Exception e){
        return new CryptException(prefix+":"+e.getMessage(), e.getCause());
    }
    public static CryptException of(String message){
        return new CryptException(message);
    }
}
