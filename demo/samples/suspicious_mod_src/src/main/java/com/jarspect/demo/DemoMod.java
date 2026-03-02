package com.jarspect.demo;

import java.util.Base64;

public final class DemoMod {
    private DemoMod() {
    }

    public static void main(String[] args) {
        System.out.println("Jarspect synthetic demo mod: safe execution path");
    }

    // This method is intentionally never invoked.
    // It exists only to provide suspicious-looking strings for scanner demos.
    private static String suspiciousButBenignSnippet() {
        String remote = "https://payload.example.invalid/bootstrap";
        String commandLike = "Runtime.getRuntime().exec(\"powershell -enc ...\")";
        String encoded = Base64.getEncoder().encodeToString(
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ".getBytes()
        );
        return remote + " | " + commandLike + " | " + encoded;
    }

    // This method is intentionally never invoked.
    // It exists only to emit a deterministic new String(new byte[]{...}) bytecode pattern.
    private static String reconstructedStringFixture() {
        return new String(new byte[] { 72, 101, 108, 108, 111 });
    }
}
