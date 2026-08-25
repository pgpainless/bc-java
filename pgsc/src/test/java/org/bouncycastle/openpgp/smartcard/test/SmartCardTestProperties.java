package org.bouncycastle.openpgp.smartcard.test;

import org.bouncycastle.openpgp.smartcard.yubikey.YubikeyTestPropertiesProvider;
import org.bouncycastle.util.Arrays;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class SmartCardTestProperties
{
    public static final char[] DEFAULT_ADMIN_PIN = "12345678".toCharArray();
    public static final char[] DEFAULT_USER_PIN = "123456".toCharArray();

    private final Integer serialNumber;
    private final char[] adminPin;
    private final char[] userPin;

    public SmartCardTestProperties(Integer serialNumber)
    {
        this(serialNumber, DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN);
    }

    public SmartCardTestProperties(Integer serialNumber,
                                   char[] adminPin,
                                   char[] userPin)
    {
        this.serialNumber = serialNumber;
        this.adminPin = adminPin;
        this.userPin = userPin;
    }

    public Integer getSerialNumber()
    {
        return serialNumber;
    }

    public char[] getAdminPin()
    {
        return Arrays.clone(adminPin);
    }

    public char[] getUserPin()
    {
        return Arrays.clone(userPin);
    }

    public static SmartCardTestProperties fromFile(String fileName)
            throws FileNotFoundException
    {
        Properties properties = loadProperties(fileName);
        return new SmartCardTestProperties(
                getInteger(properties, "DEVICE_SERIAL"),
                getCharArray(properties, "ADMIN_PIN"),
                getCharArray(properties, "USER_PIN"));
    }

    private static Properties loadProperties(String propFileName)
            throws FileNotFoundException
    {
        try (InputStream in = YubikeyTestPropertiesProvider.class.getClassLoader()
                .getResourceAsStream(propFileName))
        {
            if (in == null)
            {
                throw new FileNotFoundException("Missing file '" + propFileName + "'.");
            }

            Properties p = new Properties();
            p.load(in);
            return p;
        }
        catch (FileNotFoundException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            throw new RuntimeException("Cannot parse properties from file '" + propFileName + "'.", e);
        }
    }

    private static Integer getInteger(Properties properties, String key)
    {
        if (properties == null)
        {
            return null;
        }

        String val = properties.getProperty(key);
        if (val == null)
        {
            return null;
        }

        return Integer.parseInt(val);
    }

    private static char[] getCharArray(Properties properties, String key)
    {
        if (properties == null)
        {
            return null;
        }
        String val = properties.getProperty(key);
        if (val == null)
        {
            return null;
        }
        return val.toCharArray();
    }
}
