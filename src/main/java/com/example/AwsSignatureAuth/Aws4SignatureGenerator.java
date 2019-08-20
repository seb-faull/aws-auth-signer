package com.example.AwsSignatureAuth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class Aws4SignatureGenerator {
    public static byte[] HmacSHA256(String data, byte[] key) throws Exception
    {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] generateSignatureKey(String key, String dateStamp, String regionName, String serviceName)
            throws Exception
    {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        byte[] kSigning = HmacSHA256("aws4_request", kService);
        return kSigning;
    }
}
