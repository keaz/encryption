
import com.kzone.encription.HashUtil;
import com.kzone.encription.impl.PasswordHash;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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
public class PassHashTest 
{

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException 
    {
        HashUtil hashUtil  = new PasswordHash();
        try {
            hashUtil.init();
            String createHash = hashUtil.createHash("Kasun Sameera");
            System.out.println("createHash : "+createHash);
            Boolean validateString = hashUtil.validateString("Kasun Sameera", createHash);
            System.out.println("validateString : "+validateString);
        } catch (IOException ex) {
            Logger.getLogger(PassHashTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
