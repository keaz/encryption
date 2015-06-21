package com.kzone.encription;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import javax.annotation.PostConstruct;

/**
 * 
 * @author root
 */
public interface EncryptionUtil 
{

    /**
     * Use this method to initialize the object with main configuration
     * 
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException 
     */
    @PostConstruct
    public void init()throws GeneralSecurityException, UnsupportedEncodingException,IOException;
    
    /**
     * 
     * @param rawString
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException 
     */
    public String encrypt(String rawString)throws GeneralSecurityException,UnsupportedEncodingException;
	
    /**
     * 
     * @param encryptedString
     * @return
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException 
     */
    public String decrypt(String encryptedString)throws GeneralSecurityException,UnsupportedEncodingException;
	
}
