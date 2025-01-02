package icu.secnotes.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256Test {
    public static void main(String[] args) {
        String input = "Hello";
        String hash = "";
        int count = 0;
        long startTime = System.currentTimeMillis();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            while (!hash.startsWith("00000")) {
                count++;
                String data = input + count;
                byte[] encodedhash = digest.digest(data.getBytes());
                hash = bytesToHex(encodedhash);
//                System.out.println(String.format("第 %d 次，字符串：%s，hash值：%s", count, data, hash));
            }

            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            System.out.println("Final String: " + input + count);
            System.out.println("SHA-256 Hash: " + hash);
            System.out.println("Count: " + count);
            System.out.println("Duration: " + duration + "ms");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
