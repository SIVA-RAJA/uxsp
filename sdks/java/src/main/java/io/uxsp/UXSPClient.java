package io.uxsp;

import java.nio.charset.StandardCharsets;

/**
 * UXSP Java / Android Client SDK.
 */
public class UXSPClient {

    public static class Envelope {
        public String version = "UXSP-1";
        public String senderId;
        public String recipientId;
        public long timestamp;
        public String envelopeNonce;
        public String ciphertext;
        public String nonce;
        public String ephemeralPub;
        public String kemCiphertext;
        public String classicalSig;
        public String pqcSig;
    }

    public static byte[] bindFields(byte[]... fields) {
        int totalLen = 0;
        for (byte[] f : fields) {
            totalLen += 4 + f.length;
        }
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] f : fields) {
            result[offset] = (byte) ((f.length >> 24) & 0xFF);
            result[offset + 1] = (byte) ((f.length >> 16) & 0xFF);
            result[offset + 2] = (byte) ((f.length >> 8) & 0xFF);
            result[offset + 3] = (byte) (f.length & 0xFF);
            System.arraycopy(f, 0, result, offset + 4, f.length);
            offset += 4 + f.length;
        }
        return result;
    }
}
