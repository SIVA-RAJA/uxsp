using System;
using UXSP.Client;

namespace UXSP.Client.Tests;

public class UXSPClientTests
{
    public static void TestEnvelopeSerialization()
    {
        var env = new UXSPEnvelope
        {
            Version = "UXSP-1",
            SenderId = "alice",
            RecipientId = "bob",
            Timestamp = 1700000000,
            EnvelopeNonce = "1234567890abcdef1234567890abcdef",
            Ciphertext = "aabbcc",
            Nonce = "00112233445566778899aabb",
            EphemeralPub = "1122334455667788990011223344556677889900112233445566778899001122",
            KemCiphertext = "",
            ClassicalSig = "ff",
            PqcSig = ""
        };

        string json = UXSPClient.SerializePackage(env);
        if (string.IsNullOrEmpty(json))
        {
            throw new Exception("Serialization returned empty string");
        }

        var parsed = UXSPClient.ParsePackage(json);
        if (parsed == null || parsed.SenderId != "alice" || parsed.RecipientId != "bob")
        {
            throw new Exception("Deserialization validation failed");
        }
    }
}
