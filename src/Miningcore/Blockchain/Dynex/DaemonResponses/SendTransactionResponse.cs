using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.DaemonResponses;

public class SendTransactionResponse
{
    /// <summary>
    /// Publically searchable transaction hash
    /// </summary>
    [JsonProperty("transactionHash")]
    public string TxHash { get; set; }

    public string Status { get; set; }
}