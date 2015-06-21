
import com.kzone.encription.EncryptionUtil;
import com.kzone.encription.impl.EncryptionUtilImpl;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author root
 */
public class EncryptionUtilTest
{
    public static void main(String[] args)
    {
        EncryptionUtil eu  = new EncryptionUtilImpl();
        try
        {
            eu.init();
            String encrypt = eu.encrypt("Kasun");
            System.out.println("encrypt : "+encrypt);
            
            String decrypt = eu.decrypt(encrypt);
            System.out.println("decrypt : "+decrypt);
        }
        catch (GeneralSecurityException | UnsupportedEncodingException ex)
        {
            Logger.getLogger(EncryptionUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (IOException ex)
        {
            Logger.getLogger(EncryptionUtilTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
 
}
