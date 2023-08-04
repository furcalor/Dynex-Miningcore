using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.DaemonRequests;

public class SubmitBlockRequest
{
    [JsonProperty("blobhex")]
    public string[] Blobhex { get; set; }
    
    [JsonProperty("mallob")]
    public string Mallob { get; set; }
}
