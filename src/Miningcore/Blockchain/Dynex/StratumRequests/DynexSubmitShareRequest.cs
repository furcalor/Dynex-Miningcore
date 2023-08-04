using Newtonsoft.Json;

namespace Miningcore.Blockchain.Dynex.StratumRequests;

public class DynexSubmitShareRequest
{
    [JsonProperty("id")]
    public string WorkerId { get; set; }

    [JsonProperty("job_id")]
    public string JobId { get; set; }

    public string Nonce { get; set; }

        [JsonProperty("result")]
        public string Result { get; set; }

        [JsonProperty("algo")]
        public string Algorithm { get; set; }

        [JsonProperty("mallob")]
        public string Mallob { get; set; }

        [JsonProperty("POUW_DATA")]
        public string PouwData { get; set; }

//    [JsonProperty("result")]
//    public string Result { get; set; }

//    [JsonIgnore]
//    public string Hash
//    {
//        get
//        {
//            dynamic jsonObject = JsonConvert.DeserializeObject(JsonString);
//            return jsonObject.result;
//        }
//    }
}
