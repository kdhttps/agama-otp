package org.gluu.agama.totp;

import java.security.SecureRandom;
import com.lochbridge.oath.otp.*;
import com.lochbridge.oath.otp.keyprovisioning.*;
import com.lochbridge.oath.otp.TOTP;
import com.lochbridge.oath.otp.keyprovisioning.OTPAuthURIBuilder;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;
import java.util.concurrent.TimeUnit;
import com.google.common.io.BaseEncoding;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class TOTPUtil {

    private static final String DIGITS = 6;
    private static final String TIME_STEP = 30;

    public TOTPUtil() {
    }

    // Method to generate a secret key using SecureRandom
    public static String generateSecretKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(secureRandom);

        Key secretKey = keyGenerator.generateKey();

        // Helper method to convert byte array to hexadecimal string
        byte[] bytes = secretKey.getEncoded();
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    // Method to generate TOTP Secret URI
    public static String generateTotpSecretKeyUri(String secretKey, String issuer, String userDisplayName) {
        String secretKeyBase32 = base32Encode(secretKey);
        OTPKey key = new OTPKey(secretKeyBase32, OTPType.TOTP);
        String label = issuer + " " + userDisplayName;

        OTPAuthURI uri = OTPAuthURIBuilder.fromKey(key).label(label).issuer(issuer).digits(DIGITS)
                .timeStep(TimeUnit.SECONDS.toMillis(TIME_STEP)).build();
        return uri.toUriString();
    }

    // Method to validate TOTP
    public static boolean validateTOTP(String clientTOTP, String secretKey) {
        byte[] key = secretKey.getBytes();
        TOTP totp = TOTP.key(key).timeStep(TimeUnit.SECONDS.toMillis(TIME_STEP)).digits(DIGITS).hmacSha1().build();
        if (totp.value().equals(clientTOTP)) {
            return true
        } else {
            return false
        }
    }

    private static String base32Encode(String input) {
        byte[] bytesToEncode = input.getBytes();
        return BaseEncoding.base32().omitPadding().encode(bytesToEncode);
    }

    private static String base64URLEncode(String input) {
        byte[] bytesToEncode = input.getBytes();
        return BaseEncoding.base64Url().encode(bytesToEncode);
    }

    private static String base64UrlDecode(String input) {
        byte[] decodedBytes = BaseEncoding.base64Url().decode(input);
        return new String(decodedBytes);
    }
}
