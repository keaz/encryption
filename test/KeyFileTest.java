import com.kzone.encription.InitKeyFile;

/**
 * Created by root on 10/9/15.
 */
public class KeyFileTest
{

    public static void main(String[] args)
    {
        System.out.println( InitKeyFile.getProperty("encrypt.key"));
    }
}
