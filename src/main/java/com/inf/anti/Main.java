package com.inf.anti;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HexFormat;

public class Main {

    static {
        Logger.init(Path.of("./"), Logger.Level.INFO, 10);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: -e (encrypt) | -d (decrypt)");
            return;
        }
        if (args[0].equals("-e")) {
            encrypt();
        } else if (args[0].equals("-d")) {
            decrypt();
        } else {
            System.out.println("Usage: -e (encrypt) | -d (decrypt)");
        }
    }

    private static void encrypt() throws Exception {
        System.out.print("Content: ");
        byte[] data = readLine().getBytes(StandardCharsets.UTF_8);
        byte[] pswd = readPassword("Password: ").getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[32];
        byte[] mac = new byte[32];
        new Crypter(1 << 20).encryption(pswd, data, salt, mac);
        byte[] combined = new byte[salt.length + data.length + mac.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(data, 0, combined, salt.length, data.length);
        System.arraycopy(mac, 0, combined, salt.length + data.length, mac.length);
        Logger.info("Encrypted: %s".formatted(HexFormat.of().formatHex(combined)));
    }

    private static void decrypt() throws Exception {
        System.out.print("Hex: ");
        byte[] combined = HexFormat.of().parseHex(readLine().trim());
        byte[] pswd = readPassword("Password: ").getBytes(StandardCharsets.UTF_8);
        if (combined.length < 64) {
            throw new IllegalArgumentException("hex too short");
        }
        byte[] salt = new byte[32];
        byte[] mac = new byte[32];
        byte[] data = new byte[combined.length - 64];
        System.arraycopy(combined, 0, salt, 0, 32);
        System.arraycopy(combined, 32, data, 0, data.length);
        System.arraycopy(combined, combined.length - 32, mac, 0, 32);
        new Crypter(1 << 20).decryption(pswd, data, salt, mac);
        Logger.info("Decrypted: %s".formatted(new String(data, StandardCharsets.UTF_8)));
    }

    private static String readLine() throws Exception {
        return new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
    }

    private static String readPassword(String prompt) throws Exception {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword(prompt);
            return new String(chars);
        }
        System.out.print(prompt);
        return new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
    }
}
