package io.github.xhom.crypt.comm;

/**
 * 加密业务异常
 * @author xhom
 * @version 1.0.0
 */
public class CryptException extends RuntimeException {
    /**
     * 带消息的构造函数
     * @param message 消息
     */
    public CryptException(String message) {
        super(message);
    }

    /**
     * 带消息和异常的构造函数
     * @param message 消息
     * @param cause 原始异常
     */
    public CryptException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 通过前缀和异常创建当前类的实例
     * @param prefix 前缀
     * @param e 异常
     * @return 业务异常
     */
    public static CryptException of(String prefix, Exception e){
        return new CryptException(prefix+":"+e.getMessage(), e.getCause());
    }

    /**
     * 通过异常消息创建当前类的实例
     * @param message 消息
     * @return 业务异常
     */
    public static CryptException of(String message){
        return new CryptException(message);
    }
}
