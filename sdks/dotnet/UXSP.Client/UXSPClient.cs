using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UXSP.Client;

public class UXSPEnvelope
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "UXSP-1";

    [JsonPropertyName("sender_id")]
    public string SenderId { get; set; } = string.Empty;

    [JsonPropertyName("recipient_id")]
    public string RecipientId { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public ulong Timestamp { get; set; }

    [JsonPropertyName("envelope_nonce")]
    public string EnvelopeNonce { get; set; } = string.Empty;

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("ephemeral_pub")]
    public string EphemeralPub { get; set; } = string.Empty;

    [JsonPropertyName("kem_ciphertext")]
    public string KemCiphertext { get; set; } = string.Empty;

    [JsonPropertyName("classical_sig")]
    public string ClassicalSig { get; set; } = string.Empty;

    [JsonPropertyName("pqc_sig")]
    public string PqcSig { get; set; } = string.Empty;
}

public static class NativeMethods
{
    private const string LibName = "uxsp_core";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uxsp_generate_keypair_hex_c")]
    public static extern IntPtr UxspGenerateKeyPairHex();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uxsp_seal_c")]
    public static extern IntPtr UxspSeal(
        byte[] plaintext, UIntPtr plaintextLen,
        string sSigPriv, string sPqcPriv, string sExPriv, string sKemPriv,
        string rExPub, string rKemPub,
        string senderId, string recipientId);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uxsp_open_seal_c")]
    public static extern int UxspOpenSeal(
        string envelopeJson, string rExPriv, string rKemPriv,
        string sSigPub, string sPqcPub,
        byte[] outBuf, UIntPtr outMaxLen, out UIntPtr outLen);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uxsp_free_string")]
    public static extern void UxspFreeString(IntPtr str);
}

public class UXSPClient
{
    public static string SerializePackage(UXSPEnvelope envelope)
    {
        return JsonSerializer.Serialize(envelope);
    }

    public static UXSPEnvelope? ParsePackage(string json)
    {
        return JsonSerializer.Deserialize<UXSPEnvelope>(json);
    }
}
