using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.DaemonRequests;

public class PoolService
{
    /// <summary>
    /// Address of wallet to receive coinbase transactions if block is successfully mined.
    /// </summary>
    [JsonProperty("vlidate224")]
    public string validate224 { get; set; }
}
