package org.bouncycastle.bcpg.sig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

public class KeyServerPreferences
        extends SignatureSubpacket
{

    public enum Preference
    {
        NO_MODIFY (0x80),
        ;

        static Map<Integer, Preference> MAP = new HashMap<>();
        static
        {
            for (Preference preference : values())
            {
                MAP.put(preference.getCode(), preference);
            }
        }

        public static Preference fromCode(int code)
        {
            return MAP.get(code);
        }

        private final int code;

        public int getCode()
        {
            return code;
        }

        Preference(int code)
        {
            this.code = code;
        }
    }

    private final List<Preference> preferences = new ArrayList<>();

    protected static byte[] preferencesToBytes(List<Preference> preferences)
    {
        byte[] bytes = new byte[preferences.size()];
        for (int i = 0; i < bytes.length; i++)
        {
            bytes[i] = (byte) preferences.get(i).getCode();
        }
        return bytes;
    }

    protected static List<Preference> bytesToPreferences(byte[] data)
    {
        List<Preference> preferences = new ArrayList<>();
        for (byte b : data)
        {
            preferences.add(Preference.fromCode(b & 0xff));
        }
        return preferences;
    }

    public KeyServerPreferences(boolean critical, List<Preference> preferences)
    {
        super(SignatureSubpacketTags.KEY_SERVER_PREFS, critical, false, preferencesToBytes(preferences));
        this.preferences.addAll(preferences);
    }

    public KeyServerPreferences(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.KEY_SERVER_PREFS, critical, isLongLength, data);
        this.preferences.addAll(bytesToPreferences(data));
    }

    public List<Preference> getPreferences() {
        return new ArrayList<>(preferences);
    }
}
