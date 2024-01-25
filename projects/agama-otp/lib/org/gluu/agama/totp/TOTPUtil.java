package org.gluu.agama.totp;

import java.security.SecureRandom;
import com.lochbridge.oath.otp.*;
import com.lochbridge.oath.otp.keyprovisioning.*;
import com.lochbridge.oath.otp.TOTP;
import com.lochbridge.oath.otp.keyprovisioning.OTPAuthURIBuilder;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey;
import com.lochbridge.oath.otp.keyprovisioning.OTPKey.OTPType;
import com.lochbridge.oath.otp.HmacShaAlgorithm;
import java.util.concurrent.TimeUnit;
import com.google.common.io.BaseEncoding;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TOTPUtil {

    private static final Logger logger = LoggerFactory.getLogger(TOTPUtil.class);
    private static final int DIGITS = 6;
    private static final int TIME_STEP = 30;

    public TOTPUtil() {
    }

    // Method to generate a secret key using SecureRandom
    public static String generateSecretKey(String alg) throws NoSuchAlgorithmException {
        int keyLen = 0
        if (alg.equals('sha1')) {
            keyLen = 20
        } else if (alg.equals('sha256')) {
            keyLen = 32
        } else if (alg.equals('sha512')) {
            keyLen = 64
        } else {
            logger.error("generateSecretKey. Invalid Alg", alg);
        }
        logger.debug("generateSecretKey. keyLen ", keyLen);
        byte[] randomBytes = new byte[keyLen];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomBytes);

        StringBuilder result = new StringBuilder();
        for (byte b : randomBytes) {
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
    public static boolean validateTOTP(String clientTOTP, String secretKey, String alg) {
        byte[] key = secretKey.getBytes();
        HmacShaAlgorithm algorithm = null

        if (alg.equals('sha1')) {
            algorithm = HmacShaAlgorithm.HMAC_SHA_1
        } else if (alg.equals('sha256')) {
            algorithm = HmacShaAlgorithm.HMAC_SHA_256
        } else if (alg.equals('sha512')) {
            algorithm = HmacShaAlgorithm.HMAC_SHA_512
        } else {
            logger.error("validateTOTP. Invalid Alg", alg);
        }

        logger.debug("genervalidateTOTPateSecretKey. algorithm ", algorithm);
        TOTP totp = TOTP.key(key).timeStep(TimeUnit.SECONDS.toMillis(TIME_STEP)).digits(DIGITS).hmacSha(algorithm).build();
        logger.debug("genervalidateTOTPateSecretKey. clientTOTP ", clientTOTP);
        logger.debug("genervalidateTOTPateSecretKey. totp ", totp.value());
        
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
