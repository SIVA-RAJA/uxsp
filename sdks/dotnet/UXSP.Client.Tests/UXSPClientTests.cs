using System;
using System.Collections.Generic;
using System.Text;
using UXSP.Client;

namespace UXSP.Client.Tests;

public class UXSPClientTests
{
    public static void RunAllTests()
    {
        TestBindFields();
        TestIdentityAndPublicCard();
        TestEnvelopeSerialization();
        TestSealAndOpenSeal();
        TestHeadersAndNegotiation();
        TestSecurePackageWorkflow();
        TestReplayDetection();
    }

    public static void TestBindFields()
    {
        byte[] f1 = Encoding.UTF8.GetBytes("UXSP-1");
        byte[] f2 = Encoding.UTF8.GetBytes("Hello .NET SDK");
        byte[] bound = UXSPClient.BindFields(f1, f2);

        if (bound.Length != 4 + f1.Length + 4 + f2.Length)
        {
            throw new Exception($"BindFields length mismatch: expected {4 + f1.Length + 4 + f2.Length}, got {bound.Length}");
        }
    }

    public static void TestIdentityAndPublicCard()
    {
        var alice = Identity.Create("alice", "CLIENT");
        if (string.IsNullOrEmpty(alice.EntityId) || alice.Name != "alice")
        {
            throw new Exception("Identity creation failed.");
        }

        var card = alice.GetPublicCard();
        if (card.EntityId != alice.EntityId || string.IsNullOrEmpty(card.ExchangePub))
        {
            throw new Exception("PublicCard generation failed.");
        }
    }

    public static void TestEnvelopeSerialization()
    {
        var env = new UXSPEnvelope
        {
            Version = "UXSP-1",
            SenderId = "alice",
            RecipientId = "bob",
            Timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            EnvelopeNonce = "1234567890abcdef1234567890abcdef",
            Ciphertext = "aabbcc",
            Nonce = "00112233445566778899aabb",
            EphemeralPub = "1122334455667788990011223344556677889900112233445566778899001122",
            KemCiphertext = "",
            ClassicalSig = "ff",
            PqcSig = ""
        };

        string json = UXSPClient.SerializeEnvelope(env);
        if (string.IsNullOrEmpty(json))
        {
            throw new Exception("Serialization returned empty string");
        }

        var parsed = UXSPClient.ParseEnvelope(json);
        if (parsed == null || parsed.SenderId != "alice" || parsed.RecipientId != "bob")
        {
            throw new Exception("Deserialization validation failed");
        }
    }

    public static void TestSealAndOpenSeal()
    {
        var alice = Identity.Create("alice");
        var bob = Identity.Create("bob");

        byte[] plaintext = Encoding.UTF8.GetBytes("Cross-platform .NET message");
        var env = UXSPClient.Seal(plaintext, alice, bob.GetPublicCard());

        if (env.SenderId != alice.EntityId || env.RecipientId != bob.EntityId)
        {
            throw new Exception("Envelope metadata mismatch");
        }

        byte[] decrypted = UXSPClient.OpenSeal(env, bob, alice.GetPublicCard());
        if (decrypted.Length == 0)
        {
            throw new Exception("Decryption returned empty payload");
        }
    }

    public static void TestHeadersAndNegotiation()
    {
        var headers = UXSPClient.BuildHeaders("alice");
        if (headers["X-UXSP-Sender"] != "alice" || headers["Sec-UXSP-Support"] != "v1.2, ml-kem-768")
        {
            throw new Exception("Header generation mismatch");
        }

        var resSupported = UXSPClient.InspectResponseNegotiation(new Dictionary<string, string>
        {
            ["Sec-UXSP-Selected"] = "v1.2"
        });
        if (!resSupported.IsUXSPSupported || resSupported.SelectedVersion != "v1.2")
        {
            throw new Exception("Negotiation inspection failed for supported response");
        }

        var resUnsupported = UXSPClient.InspectResponseNegotiation(new Dictionary<string, string>
        {
            ["Content-Type"] = "application/json"
        });
        if (resUnsupported.IsUXSPSupported)
        {
            throw new Exception("Negotiation inspection failed for unsupported response");
        }
    }

    public static void TestSecurePackageWorkflow()
    {
        var alice = Identity.Create("alice");
        var bob = Identity.Create("bob");

        byte[] data = Encoding.UTF8.GetBytes("Package workflow test");
        var pkg = UXSPClient.CreateEncryptedPackage(alice, bob.GetPublicCard(), data, "TEXT", new Dictionary<string, object> { ["test"] = true });

        string json = UXSPClient.SerializePackage(pkg);
        var parsed = UXSPClient.ParsePackage(json);

        if (parsed == null || parsed.SenderId != alice.EntityId)
        {
            throw new Exception("SecurePackage parsing mismatch");
        }

        byte[] decrypted = UXSPClient.OpenEncryptedPackage(bob, alice.GetPublicCard(), parsed);
        if (decrypted.Length == 0)
        {
            throw new Exception("OpenEncryptedPackage returned empty result");
        }
    }

    public static void TestReplayDetection()
    {
        ulong ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string nonce = "test_replay_nonce_12345";

        UXSPClient.VerifyFreshnessAndNonce(nonce, ts);

        try
        {
            UXSPClient.VerifyFreshnessAndNonce(nonce, ts);
            throw new Exception("Expected replay attack exception, but none was thrown");
        }
        catch (InvalidOperationException)
        {
            // Expected
        }
    }
}
