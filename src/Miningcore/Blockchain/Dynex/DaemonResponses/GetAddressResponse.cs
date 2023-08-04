using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.DaemonResponses;

public class GetAddressResponse
{
    [JsonProperty("addresses")]
    public string[] Address { get; set; }
}