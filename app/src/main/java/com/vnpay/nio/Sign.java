package com.vnpay.nio;

import android.text.TextUtils;

import com.vnpay.bc.AESCipher;
import com.vnpay.bc.Base64;
import com.vnpay.security.UtilSecurity;

import org.json.JSONObject;

import java.io.UnsupportedEncodingException;

/**
 * Created by LeHieu on 4/10/2017.
 */

public class Sign {
    public static String RSA_PUBLIC_MASTER = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnhVV2Zxb1FtbFJMaXNZd1hPNW9XVzVZVWZMWGNCbVhhRzNyK0xZb25HUzdJQnBVMzFFNnU5VEdyMndjZVp5SEk2M2U3eklpcTJzRGFUbnA1cWMvZ2l1OUxtUENtc2M5OHNoSXFiVjhRUnlvcE1DS1lxcGppNzMxczc2dTJOY0t6bUdpUTZIMTNjRkRDZ1ozL09ycklnVWJxN1llNzZQbjBuMUVERGdLcnYzYz08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjE4MXNDZzZCZCs4NkNRc0thbDN2dERzQkVSKzdrT1hiVW96eFVBelhMWnNQUGFtbTNMaHBkbXRkT1FWL0RmTllXK0hycFZJWXA5WWFRT0p0UUtGUnBRPT08L1A+PFE+NmdTU3ZsK3VON2hsUExGem01L0ZpN0xOeldjUDQxR2FkOXd6RFlMa0VqdUNTVUUxLzY0QzI4aG4zTi9MS2xlbFNUWWVIcjFodytZSi8zOTJYQ3NKNnc9PTwvUT48RFA+Ulp4SndXUzBkbytBVlBKdXhhalBiWCtxOUc4Yi9iMW5aZFY0OGExeXE0OWM5ek1HVkNSWVFJNlpYNDlhVUpHeWF0RVJSaDZaUFdwZXhaZEVUcGk2MFE9PTwvRFA+PERRPjJhY3JQTGtNOW5JZ1pwUzg2NjlzTW9RNCthT3ptVDlhcGNRK0Q0RC8weDFhRGZ3QzF5em5KN2Q3TW1sTE1yU1YzRVBqTzcvMFlCbGlqeW5qMGRHTnhRPT08L0RRPjxJbnZlcnNlUT5GdnBYaG9rSi9UMU5FdVRiVnBKcHZ2K3cydTNZVDk2VkxoMmkySTFhN3MyNVhwOFY5a1l0MHdIUTNZYitIamFsQjl1a1pZYTY4OVhjOVpxNHpOSmFXQT09PC9JbnZlcnNlUT48RD5Qd05jV3hWWFZhcndxcEg3SWRpNFo0enJBbUw4NHpaSmt4bVljMmQ3MGJsMXYxU092c3hiYW9yeFFFZG4yTDJiOWtzS3UreXoxcWhmazAzZjZ2UXgzdCtkeGpZdXhySHdWODdoRnVFMjQxRVVvcDhocmt1Q1VwOXlDTkR2elpaYmo4VW9TdktxQXNLZlNXMllDNUZERW5id2JEeW1xYkhZTE1kRkU4dnlyWEU9PC9EPjwvUlNBS2V5VmFsdWU+";
    public static final String SEPERATOR_NEW_SIGNATURE = new String(
            new byte[]{(byte) (8)});
    public static final String SEPERATOR_NEW_ELEMENT = new String(
            new byte[]{(byte) (1)});
    public static String keyId = "1e08b52632a2419f9e47612ff99497de";

    public static final String MASTER_KEY = "@[B7b479";
    public static byte[] ivAsByte = "@5f2rv8pa1yW14I3".getBytes();
    public static final String SEPERATOR_NEW_5 = new String(
            new byte[]{(byte) (5)});
    public static final String SEPERATOR_DIFF_MESSAGE = new String(new byte[] { (byte) (6) });

    public static byte[] SignData(String rawData) {
        StringBuilder sb = new StringBuilder();
        sb.append(rawData);
        String rsaPublic = new String(Base64.decode(RSA_PUBLIC_MASTER));
        String signature = UtilSecurity.signtRSA(rawData, rsaPublic, "base64");
        sb.append(SEPERATOR_NEW_SIGNATURE)
                .append(keyId)
                .append(SEPERATOR_NEW_ELEMENT)
                .append(signature);
        byte[] outData = sb.toString().getBytes();
        outData = AESCipher.AESFastEncrypt(outData, MASTER_KEY, ivAsByte);
        return outData;
    }

    public static String decode(byte[] input) throws UnsupportedEncodingException {
        StringBuilder lstRequests = new StringBuilder();

        byte[] decryptB = AESCipher.AESFastDecrypt(input, MASTER_KEY, ivAsByte);
        String data = new String(decryptB, "UTF-8");
        int index = data.indexOf("\u0000");

        if (index > 0) data = data.substring(0, index);
        lstRequests.append(data).append(SEPERATOR_NEW_5);
        if (lstRequests.length() > 0) {
            lstRequests.deleteCharAt(lstRequests.length() - 1);
        }
        return lstRequests.toString();
    }
}
