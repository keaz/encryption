package com.kzone.encription;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author root
 */
public interface HashUtil 
{

    /**
     * Use this method to initialize the object with main configuration
     * 
     * @throws IOException 
     */
    public void init()throws IOException;
    
    /**
     * Returns a salted PBKDF2 hash of the password.
     *
     * @param rawString the password to hash
     * @return a salted PBKDF2 hash of the password
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public String createHash(String rawString) throws NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Validates a password using a hash.
     *
     * @param password the password to check
     * @param correctHash the hash of the valid password
     * @return true if the password is correct, false if not
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public Boolean validateString(String password, String correctHash) throws NoSuchAlgorithmException, InvalidKeySpecException;

}
