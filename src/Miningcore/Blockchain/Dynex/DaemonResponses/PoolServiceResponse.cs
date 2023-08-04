using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.DaemonResponses
{
    public class PoolServiceResponse
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("error")]
        public object Error { get; set; }

        [JsonProperty("result")]
        public long Result { get; set; }
    }
}
