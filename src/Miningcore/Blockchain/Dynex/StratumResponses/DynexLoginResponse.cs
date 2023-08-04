using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.StratumResponses;

public class DynexJobParams
{
    [JsonProperty("job_id")]
    public string JobId { get; set; }

    [JsonProperty("id")]
    public string Id { get; set; }

    public string Blob { get; set; }
    public string Target { get; set; }
}

public class DynexLoginResponse : DynexResponseBase
{
    public string Id { get; set; } = "1";
    public DynexJobParams Job { get; set; }
}
