package com.kzone.encription;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Created by root on 10/9/15.
 */
public class InitKeyFile
{

    private static Properties keyProperties = null;

    private static void loadKeyFile()
    {
        if (keyProperties == null)
        {
            InputStream input = ClassLoader.getSystemClassLoader().getResourceAsStream("./security.properties");
            if (input == null)
            {
                System.err.printf("There is no %s the default package. Will use the internal property file %n","security.properties");
                System.out.printf("Loading %s file %n","security_internal.properties");
                input  =  InitKeyFile.class.getResourceAsStream("security_internal.properties");

            }
            else
            {
                System.out.printf("Loading %s file %n","security.properties");
            }

            try
            {
                keyProperties = new Properties();
                keyProperties.load(input);
                System.out.println(keyProperties);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
    }


    public static String getProperty(String key)
    {
        loadKeyFile();
        return keyProperties.getProperty(key);
    }

}
