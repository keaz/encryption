package com.kzone.encription.impl;

import com.kzone.encription.EncryptionUtil;
import com.kzone.encription.InitKeyFile;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.RuntimeException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;
import java.util.Properties;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

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

        String    stringShout  =  InitKeyFile.getProperty("shout");
        this.shout  = stringShout  == null ? Boolean.FALSE : Boolean.valueOf(stringShout);

        String    stringKeay      =  InitKeyFile.getProperty("encrypt.key");
        String    algorithm       =  InitKeyFile.getProperty("encrypt.algorithm");
        String    encrtyptcipher  =  InitKeyFile.getProperty("encrypt.cipher");

        if(stringKeay == null)
        {
            throw new RuntimeException("Encryption key is null! Please set add the encrypt.key to security.properties");
        }

        if(algorithm == null)
        {
            throw new RuntimeException("Encryption algorithm is null! Please set add the encrypt.algorithm to security.properties");
        }

        if(algorithm == null)
        {
            throw new RuntimeException("Encryption algorithm is null! Please set add the encrypt.cipher to security.properties");
        }

        byte[] bytes = stringKeay.getBytes("UTF-8");
        int length = bytes.length;

        if(!(length == 16 || length == 24 || length == 32))
        {
            throw new RuntimeException("Key length not 16/24/32 bytes");
        }

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
                System.err.printf("Encrypting the {%s}%n",rawString);
            }
            return Base64.getEncoder().encodeToString(cipher.doFinal(rawString.getBytes("UTF-8")));

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
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(encryptedString));
            return new String(plainText, "UTF-8");

        }
        catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            throw e;
        }

    }

}
