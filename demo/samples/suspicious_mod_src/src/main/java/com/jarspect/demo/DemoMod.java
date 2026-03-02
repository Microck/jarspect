package com.jarspect.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class DemoMod {
    private DemoMod() {
    }

    public static void main(String[] args) {
        System.out.println("Jarspect synthetic demo mod: safe execution path");
    }

    // Never invoked: fixture for DETC-01 execution primitives.
    private static void detc01ExecFixture() {
        try {
            Runtime.getRuntime().exec(new String[] { "powershell", "-Command", "Write-Output demo" });
        } catch (Exception ignored) {
        }

        try {
            new ProcessBuilder("cmd.exe", "/c", "echo", "demo").start();
        } catch (Exception ignored) {
        }
    }

    // Never invoked: fixture for DETC-02 networking primitives + URL strings.
    private static void detc02NetworkFixture() {
        try {
            URL url = new URL("https://example.invalid/api/bootstrap");
            URLConnection connection = url.openConnection();
            connection.connect();
        } catch (Exception ignored) {
        }

        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress("example.invalid", 443));
            socket.close();
        } catch (Exception ignored) {
        }

        try {
            DatagramSocket datagramSocket = new DatagramSocket();
            byte[] payload = "demo".getBytes(StandardCharsets.UTF_8);
            DatagramPacket packet = new DatagramPacket(
                payload,
                payload.length,
                InetAddress.getByName("127.0.0.1"),
                9
            );
            datagramSocket.send(packet);
            datagramSocket.close();
        } catch (Exception ignored) {
        }
    }

    // Never invoked: fixture for DETC-03 dynamic loading + reflection primitives.
    private static void detc03DynamicLoadFixture() {
        try {
            URL[] urls = new URL[] { new URL("https://example.invalid/loader.jar") };
            URLClassLoader loader = new URLClassLoader(urls);
            Class<?> runtimeClass = Class.forName("java.lang.Runtime");
            Method getRuntime = runtimeClass.getMethod("getRuntime");
            getRuntime.invoke(null);
            Constructor<String> constructor = String.class.getConstructor(String.class);
            constructor.newInstance("demo");
            String sensitiveTokens = "java/lang/Runtime exec defineClass loadLibrary";
            sensitiveTokens.length();
            loader.close();
        } catch (Exception ignored) {
        }
    }

    // Never invoked: fixture for DETC-04 archive/file modification primitives.
    private static void detc04ArchiveWriteFixture() {
        try {
            String traversalTarget = "mods/../payload.jar";
            ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
            ZipOutputStream zipOutputStream = new ZipOutputStream(zipBytes);
            zipOutputStream.putNextEntry(new ZipEntry(traversalTarget));
            zipOutputStream.write("demo".getBytes(StandardCharsets.UTF_8));
            zipOutputStream.closeEntry();
            zipOutputStream.close();

            ByteArrayOutputStream jarBytes = new ByteArrayOutputStream();
            JarOutputStream jarOutputStream = new JarOutputStream(jarBytes);
            jarOutputStream.putNextEntry(new JarEntry("mods/demo.jar"));
            jarOutputStream.write("demo".getBytes(StandardCharsets.UTF_8));
            jarOutputStream.closeEntry();
            jarOutputStream.close();
        } catch (Exception ignored) {
        }
    }

    // Never invoked: fixture for DETC-05 persistence markers correlated with exec/write primitives.
    private static void detc05PersistenceFixture() {
        try {
            String runKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            String schtasks = "schtasks /Create /SC ONLOGON /TN DemoTask";
            String systemd = "/etc/systemd/system/demo.service";
            Path persistencePath = Paths.get("demo-persistence-marker.txt");
            Files.write(persistencePath, (runKey + schtasks + systemd).getBytes(StandardCharsets.UTF_8));
            Runtime.getRuntime().exec(new String[] { "cmd.exe", "/c", "echo", "persist" });
        } catch (Exception ignored) {
        }
    }

    // Never invoked: fixture for DETC-06 unsafe deserialization sink.
    private static void detc06UnsafeDeserializationFixture() {
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(new byte[] { 1, 2, 3, 4 }));
            objectInputStream.readObject();
        } catch (Exception ignored) {
        }
    }

    // Never invoked: fixture for DETC-07 native library loading.
    private static void detc07NativeLoadFixture() {
        String nativePath = "/tmp/demo.so";
        try {
            System.loadLibrary("demo");
        } catch (Throwable ignored) {
        }

        try {
            System.load(nativePath);
        } catch (Throwable ignored) {
        }
    }

    // Never invoked: fixture for DETC-08 credential/token theft markers + read/network primitives.
    private static void detc08CredentialTheftFixture() {
        try {
            String loginData = "Login Data";
            String cookies = "Cookies";
            String localState = "Local State";
            String minecraftPath = ".minecraft";
            Path path = Paths.get(loginData);
            Files.readAllBytes(path);

            URL url = new URL("https://example.invalid/collector");
            URLConnection connection = url.openConnection();
            connection.connect();

            (cookies + localState + minecraftPath).length();
        } catch (Exception ignored) {
        }
    }

    // Never invoked: deterministic new String(new byte[]{...}) fixture retained for bytecode reconstruction tests.
    private static String reconstructedStringFixture() {
        return new String(new byte[] { 72, 101, 108, 108, 111 }, StandardCharsets.UTF_8);
    }
}
