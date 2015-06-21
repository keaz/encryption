package com.kzone.encription.impl;

import com.kzone.encription.EncryptionUtil;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Properties;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class EncryptionUtilImpl implements EncryptionUtil
{

    static
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private final Properties       keyProperties  =  new Properties();
    private       SecretKeySpec    key            =  null;
    private       Cipher           cipher         =  null;
    private       Boolean          shout          =  Boolean.FALSE;
    
    @Override
    public void init() throws GeneralSecurityException, UnsupportedEncodingException,IOException
    {

        loadKeyFile();
        String    stringShout  =  keyProperties.getProperty("shout");
        this.shout  = stringShout  == null ? Boolean.FALSE : Boolean.valueOf(stringShout);
        
        String    stringKeay      =  keyProperties.getProperty("encrypt.key");
        String    algorithm       =  keyProperties.getProperty("encrypt.algorithm");
        String    encrtyptcipher  =  keyProperties.getProperty("encrypt.cipher");

        assert stringKeay     != null : "Encryption key is null! Please set add the encrypt.key to security.properties";
        assert algorithm      != null : "Encryption algorithm is null! Please set add the encrypt.algorithm to security.properties";
        assert encrtyptcipher != null : "Encryption algorithm is null! Please set add the encrypt.cipher to security.properties";

        byte[] bytes = stringKeay.getBytes("UTF-8");
        int length = bytes.length;

        assert length == 16 || length == 24 || length == 32 : "Key length not 16/24/32 bytes";

        key = new SecretKeySpec(bytes, algorithm);
        try
        {
            if(shout)
            {
                System.out.printf("Creating [ciper] from {%s}%n",encrtyptcipher);
            }
            cipher = Cipher.getInstance(encrtyptcipher);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            throw e;
        }

    }

    private void loadKeyFile() throws FileNotFoundException, IOException
    {
        InputStream input = this.getClass().getClassLoader()
                            .getResourceAsStream("security.properties");
        keyProperties.load(input);
    }
    
    @Override
    public String encrypt(String rawString) throws GeneralSecurityException, UnsupportedEncodingException
    {

        assert rawString != null : "rawString is null!! give a value to encrypt";

        try
        {
            if(shout)
            {
                System.err.printf("Initializing [%s] for %s%n","ciper","encription");
            }
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            if(shout)
            {
                System.err.printf("Encripting the {%s}%n",rawString);
            }
            return Base64.encodeBase64String(cipher.doFinal(rawString.getBytes("UTF-8")));

        }
        catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            throw e;
        }
    }

    @Override
    public String decrypt(String encryptedString) throws GeneralSecurityException, UnsupportedEncodingException
    {

        assert encryptedString != null : "encryptedString is null!! give a value to decrypt";

        try
        {
            if(shout)
            {
                System.err.printf("Initializing [%s] for %s%n","ciper","decription");
            }
            cipher.init(Cipher.DECRYPT_MODE, key);
            
            if(shout)
            {
                System.err.printf("Decripting the {%s}%n",encryptedString);
            }
            byte[] plainText = cipher.doFinal(Base64.decodeBase64(encryptedString));
            return new String(plainText, "UTF-8");

        }
        catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            throw e;
        }

    }

}
