package io.uxsp;

import java.nio.charset.StandardCharsets;

public class UXSPClientTest {

    public static void main(String[] args) {
        byte[] field1 = "UXSP-1".getBytes(StandardCharsets.UTF_8);
        byte[] field2 = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] bound = UXSPClient.bindFields(field1, field2);

        if (bound.length != (4 + field1.length + 4 + field2.length)) {
            throw new RuntimeException("Length-prefixed field binding length mismatch");
        }
        System.out.println("Java UXSPClientTest passed successfully!");
    }
}
