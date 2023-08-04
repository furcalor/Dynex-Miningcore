using static System.Array;
using System.Globalization;
using System.Reactive;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Net.Http;
using Autofac;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Dynex.Configuration;
using Miningcore.Blockchain.Dynex.DaemonRequests;
using Miningcore.Blockchain.Dynex.DaemonResponses;
using Miningcore.Blockchain.Dynex.StratumRequests;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Native;
using Miningcore.Notifications.Messages;
using Miningcore.Rest;
using Miningcore.Rpc;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using Contract = Miningcore.Contracts.Contract;
using static Miningcore.Util.ActionUtils;

namespace Miningcore.Blockchain.Dynex;

public class DynexJobManager : JobManagerBase<DynexJob>
{
    public DynexJobManager(
        IComponentContext ctx,
        IMasterClock clock,
        IHttpClientFactory httpClientFactory,
        IMessageBus messageBus) :
        base(ctx, messageBus)
    {
        Contract.RequiresNonNull(ctx);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(messageBus);

        this.clock = clock;
        this.httpClientFactory = httpClientFactory;
    }

    private byte[] instanceId;
    private DaemonEndpointConfig[] daemonEndpoints;
    private IHttpClientFactory httpClientFactory;
    private SimpleRestClient restClient;
    private RpcClient rpc;
    private RpcClient walletRpc;
    private RpcClient poolserviceRpc;
    private readonly IMasterClock clock;
    private DynexNetworkType networkType;
    private DynexPoolConfigExtra extraPoolConfig;
    private ulong poolAddressBase58Prefix;
    private DaemonEndpointConfig[] walletDaemonEndpoints;
    private DaemonEndpointConfig[] poolserviceDaemonEndpoints;
    private DynexCoinTemplate coin;
    private Dictionary<string, Dictionary<string, List<(DateTime timestamp, int shareCount, double difficulty)>>> minerWorkerShareCounts = new Dictionary<string, Dictionary<string, List<(DateTime, int, double)>>>();
    private const string DefaultWorkerName = "default";

    protected async Task<bool> UpdateJob(CancellationToken ct, string via = null, string json = null)
    {
        try
        {
            var response = string.IsNullOrEmpty(json) ? await GetBlockTemplateAsync(ct) : GetBlockTemplateFromJson(json);

            // may happen if daemon is currently not connected to peers
            if(response.Error != null)
            {
                logger.Warn(() => $"Unable to update job. Daemon responded with: {response.Error.Message} Code {response.Error.Code}");
                return false;
            }

            var blockTemplate = response.Response;
            var job = currentJob;
            var newHash = blockTemplate.Blob.HexToByteArray().AsSpan().Slice(7, 32).ToHexString();

            var isNew = job == null || newHash != job.PrevHash;

            if(isNew)
            {
                messageBus.NotifyChainHeight(poolConfig.Id, blockTemplate.Height, poolConfig.Template);

                if(via != null)
                    logger.Info(() => $"Detected new block {blockTemplate.Height} [{via}]");
                else
                    logger.Info(() => $"Detected new block {blockTemplate.Height}");

                // init job
                job = new DynexJob(blockTemplate, instanceId, NextJobId(), coin, poolConfig, clusterConfig, newHash);
                currentJob = job;

                // update stats
                BlockchainStats.LastNetworkBlockTime = clock.Now;
                BlockchainStats.BlockHeight = job.BlockTemplate.Height;
                BlockchainStats.NetworkDifficulty = job.BlockTemplate.Difficulty;
                BlockchainStats.NextNetworkTarget = "";
                BlockchainStats.NextNetworkBits = "";
            }

            else
            {
                if(via != null)
                    logger.Debug(() => $"Template update {blockTemplate.Height} [{via}]");
                else
                    logger.Debug(() => $"Template update {blockTemplate.Height}");
            }

            return isNew;
        }

        catch(OperationCanceledException)
        {
            // ignored
        }

        catch(Exception ex)
        {
            logger.Error(ex, () => $"Error during {nameof(UpdateJob)}");
        }

        return false;
    }

    private async Task<RpcResponse<GetBlockTemplateResponse>> GetBlockTemplateAsync(CancellationToken ct)
    {
        var request = new GetBlockTemplateRequest
        {
            WalletAddress = poolConfig.Address,
            ReserveSize = DynexConstants.ReserveSize
        };

        return await rpc.ExecuteAsync<GetBlockTemplateResponse>(logger, DynexCommands.GetBlockTemplate, ct, request);
    }

    private RpcResponse<GetBlockTemplateResponse> GetBlockTemplateFromJson(string json)
    {
        var result = JsonConvert.DeserializeObject<JsonRpcResponse>(json);

        return new RpcResponse<GetBlockTemplateResponse>(result.ResultAs<GetBlockTemplateResponse>());
    }

    private async Task ShowDaemonSyncProgressAsync(CancellationToken ct)
    {
        var info = await restClient.Get<GetInfoResponse>(DynexConstants.DaemonRpcGetInfoLocation, ct);
        
        if(info.Status != "OK")
        {
            var lowestHeight = info.Height;

            var totalBlocks = info.TargetHeight;
            var percent = (double) lowestHeight / totalBlocks * 100;

            logger.Info(() => $"Daemon has downloaded {percent:0.00}% of blockchain from {info.OutgoingConnectionsCount} peers");
        }
    }

    private async Task UpdateNetworkStatsAsync(CancellationToken ct)
    {
        try
        {
            var coin = poolConfig.Template.As<DynexCoinTemplate>();
            var info = await restClient.Get<GetInfoResponse>(DynexConstants.DaemonRpcGetInfoLocation, ct);
            
            if(info.Status != "OK")
                logger.Warn(() => $"Error(s) refreshing network stats...");

            if(info.Status == "OK")
            {
                BlockchainStats.NetworkHashrate = info.TargetHeight > 0 ? (double) info.Difficulty / coin.DifficultyTarget : 0;
                BlockchainStats.ConnectedPeers = info.OutgoingConnectionsCount + info.IncomingConnectionsCount;
            }
        }

        catch(Exception e)
        {
            logger.Error(e);
        }
    }

    private async Task<bool> SubmitBlockAsync(Share share, string blobHex, string mallob, string blobHash)
    {
        var response = await rpc.ExecuteAsync<SubmitResponse>(logger, DynexCommands.SubmitBlock, CancellationToken.None, new[] { blobHex });

        if(response.Error != null || response?.Response?.Status != "OK")
        {
            var error = response.Error?.Message ?? response.Response?.Status;

            logger.Warn(() => $"Block {share.BlockHeight} [{blobHash}] submission failed with: {error}");
            messageBus.SendMessage(new AdminNotification("Block submission failed", $"Pool {poolConfig.Id} {(!string.IsNullOrEmpty(share.Source) ? $"[{share.Source.ToUpper()}] " : string.Empty)}failed to submit block {share.BlockHeight}: {error}"));
            return false;
        }

        return true;
    }

    #region API-Surface

    public IObservable<Unit> Blocks { get; private set; }

    public DynexCoinTemplate Coin => coin;

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(cc);

        logger = LogUtil.GetPoolScopedLogger(typeof(JobManagerBase<DynexJob>), pc);
        poolConfig = pc;
        clusterConfig = cc;
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<DynexPoolConfigExtra>();
        coin = pc.Template.As<DynexCoinTemplate>();
        
        var NetworkTypeOverride = !string.IsNullOrEmpty(extraPoolConfig?.NetworkTypeOverride) ? extraPoolConfig.NetworkTypeOverride : "testnet";
        
        switch(NetworkTypeOverride.ToLower())
        {
            case "mainnet":
                networkType = DynexNetworkType.Main;
                break;
            case "testnet":
                networkType = DynexNetworkType.Test;
                break;
            default:
                throw new PoolStartupException($"Unsupport net type '{NetworkTypeOverride}'", poolConfig.Id);
        }
        
        // extract standard daemon endpoints
        daemonEndpoints = pc.Daemons
            .Where(x => string.IsNullOrEmpty(x.Category))
            .Select(x =>
            {
                if(string.IsNullOrEmpty(x.HttpPath))
                    x.HttpPath = DynexConstants.DaemonRpcLocation;

                return x;
            })
            .ToArray();

        poolserviceDaemonEndpoints = pc.Daemons
            .Where(x => x.Category?.ToLower() == DynexConstants.PoolserviceDaemonCategory)
            .Select(x =>
            {
                if(string.IsNullOrEmpty(x.HttpPath))
                    x.HttpPath = DynexConstants.PoolServiceRpcLocation;

                return x;
            })
            .ToArray();

            if(poolserviceDaemonEndpoints.Length == 0)
                throw new PoolStartupException("PoolService-HTTP daemon is not configured (Daemon configuration for dynex-pools require an additional entry of category \'poolservice' pointing to the poolservice)", pc.Id);

        if(cc.PaymentProcessing?.Enabled == true && pc.PaymentProcessing?.Enabled == true)
        {
            // extract wallet daemon endpoints
            walletDaemonEndpoints = pc.Daemons
                .Where(x => x.Category?.ToLower() == DynexConstants.WalletDaemonCategory)
                .Select(x =>
                {
                    if(string.IsNullOrEmpty(x.HttpPath))
                        x.HttpPath = DynexConstants.DaemonRpcLocation;

                    return x;
                })
                .ToArray();

            if(walletDaemonEndpoints.Length == 0)
                throw new PoolStartupException("Wallet-RPC daemon is not configured (Daemon configuration for dynex-pools require an additional entry of category \'wallet' pointing to the wallet daemon)", pc.Id);
        }

        ConfigureDaemons();
    }

    public bool ValidateAddress(string address)
    {
        if(string.IsNullOrEmpty(address))
            return false;

        var addressPrefix = CryptonoteBindings.DecodeAddress(address);
        var addressIntegratedPrefix = CryptonoteBindings.DecodeIntegratedAddress(address);
        var coin = poolConfig.Template.As<DynexCoinTemplate>();

        switch(networkType)
        {
            case DynexNetworkType.Main:
                if(addressPrefix != coin.AddressPrefix)
                    return false;
                break;

            case DynexNetworkType.Test:
                if(addressPrefix != coin.AddressPrefixTestnet)
                    return false;
                break;
        }

        return true;
    }

    public BlockchainStats BlockchainStats { get; } = new();
    public PoolStats PoolStats { get; } = new();

    public void PrepareWorkerJob(DynexWorkerJob workerJob, out string blob, out string target)
    {
        blob = null;
        target = null;

        var job = currentJob;

        if(job != null)
        {
            lock(job)
            {
                job.PrepareWorkerJob(workerJob, out blob, out target);
            }
        }
    }

    public double CalculateHashrateForMiner(string miner, string worker)
    {
        string workerName = string.IsNullOrEmpty(worker) ? DefaultWorkerName : worker;

        if (minerWorkerShareCounts.ContainsKey(miner) && minerWorkerShareCounts[miner].ContainsKey(workerName)) 
        {
            var minerShares = minerWorkerShareCounts[miner][workerName];

            DateTime minutesAgo = DateTime.Now.AddMinutes(-10);
            double timeDurationInSeconds = (DateTime.Now - minutesAgo).TotalSeconds;
            int totalShareCount = minerShares.Sum(share => share.shareCount);
            double totalDifficulty = minerShares.Sum(share => share.difficulty);
            double averageDifficulty = totalDifficulty / totalShareCount;
            double hashrate = totalShareCount / timeDurationInSeconds;
            hashrate = hashrate * (averageDifficulty);
            return hashrate;
        }

        return 0.0;
    }

    public async ValueTask<Share> SubmitShareAsync(StratumConnection worker,
        DynexSubmitShareRequest request, DynexWorkerJob workerJob, CancellationToken ct)
    {
        Contract.RequiresNonNull(worker);
        Contract.RequiresNonNull(request);

        var context = worker.ContextAs<DynexWorkerContext>();
        var job = currentJob;
        string Mallob = request.Mallob;
        double hashrate = CalculateHashrateForMiner(context.Miner, context.Worker);
        hashrate = Math.Floor(hashrate);
        string UUID = null;
        if(!string.IsNullOrEmpty(extraPoolConfig?.UUID))
        {
            UUID = extraPoolConfig.UUID;
        }

        //Run through to get info for poolservice, also basic checks for invalid shares.
        var (convertedBlob, found_hash, shareDiff, stratumDifficulty, pouw_data, algo, blobHex) = job.PreProcessShare(request.Nonce, workerJob.ExtraNonce, request, worker);

        var toValidate = new List<string>()
        {
            request.Mallob,
            context.Miner,
            convertedBlob.ToHexString(),
            found_hash,
            shareDiff.ToString(),
            job.BlockTemplate.Difficulty.ToString(),
            job.BlockTemplate.Height.ToString(),
            hashrate.ToString(),
            UUID,
            pouw_data
        };

        var apiUrl = "http://" + poolserviceDaemonEndpoints.First().Host.ToString() + ":" + poolserviceDaemonEndpoints.First().Port.ToString() + "/validate224";

        if (algo == "dynexsolve230") {
            using (var httpClient = new HttpClient())
            {
                var payload = new
                {
                    jsonrpc = "2.0",
                    method = "validate224",
                    @params = toValidate,
                    id = context.requestId
                };

                var jsonPayload = Newtonsoft.Json.JsonConvert.SerializeObject(payload);
                var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");

                using HttpResponseMessage response = await httpClient.PostAsync(apiUrl, content);
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject jsonObject = JObject.Parse(responseBody);
                int resultValue = jsonObject.Value<int>("result");

                if (resultValue == 414) // Compare to 414 specifically
                   throw new StratumException(StratumError.MinusOne, "414 Mallob verification failed");

                if (resultValue == 499) // Compare to 414 specifically
                   throw new StratumException(StratumError.MinusOne, "499 Checkhash Failed");

                if (resultValue == 500) // Compare to 414 specifically
                   throw new StratumException(StratumError.MinusOne, "500 POUW data verification failed");

                if (resultValue != 200) // Compare to 200 specifically
                   throw new StratumException(StratumError.MinusOne, "Invalid data");
            }
        } else {
            throw new StratumException(StratumError.MinusOne, "Incorrect DynexSolve Algorithm");
        }

        //resume normal MC operations
        var (share, blobHex2) = job.ProcessShare(request.Nonce, workerJob.ExtraNonce, request, worker);

        // enrich share with common data
        share.PoolId = poolConfig.Id;
        share.IpAddress = worker.RemoteEndpoint.Address.ToString();
        share.Miner = context.Miner;
        share.Worker = context.Worker;
        share.UserAgent = context.UserAgent;
        share.Source = clusterConfig.ClusterName;
        share.NetworkDifficulty = job.BlockTemplate.Difficulty;
        share.Created = clock.Now;

        // if block candidate, submit & check if accepted by network
        if(share.IsBlockCandidate)
        {
            logger.Info(() => $"Submitting block {share.BlockHeight} [{share.BlockHash[..6]}]");

            share.IsBlockCandidate = await SubmitBlockAsync(share, blobHex2, Mallob, share.BlockHash);

            if(share.IsBlockCandidate)
            {
                logger.Info(() => $"Daemon accepted block {share.BlockHeight} [{share.BlockHash[..6]}] submitted by {context.Miner} algo {algo}");

                OnBlockFound();

                share.TransactionConfirmationData = share.BlockHash;
            }

            else
            {
                // clear fields that no longer apply
                share.TransactionConfirmationData = null;
            }
        }

        DateTime now = DateTime.Now;

        string workerName = string.IsNullOrEmpty(context.Worker) ? DefaultWorkerName : context.Worker;

        if (!minerWorkerShareCounts.ContainsKey(context.Miner))
        {
            minerWorkerShareCounts.Add(context.Miner, new Dictionary<string, List<(DateTime, int, double)>>());
        }

        if (!minerWorkerShareCounts[context.Miner].ContainsKey(workerName))
        {
            minerWorkerShareCounts[context.Miner].Add(workerName, new List<(DateTime, int, double)> { (now, 1, stratumDifficulty) });
        }
        else
        {
            var minerShares = minerWorkerShareCounts[context.Miner][workerName];
            minerShares.Add((now, 1, stratumDifficulty));

            DateTime minutesAgo = now.AddMinutes(-10);
            minerShares.RemoveAll(share => share.timestamp < minutesAgo);
        }

        return share;
    }

    #endregion // API-Surface

    private static JToken GetFrameAsJToken(byte[] frame)
    {
        var text = Encoding.UTF8.GetString(frame);

        // find end of message type indicator
        var index = text.IndexOf(":");

        if (index == -1)
            return null;

        var json = text.Substring(index + 1);

        return JToken.Parse(json);
    }

    #region Overrides

    protected override void ConfigureDaemons()
    {
        var jsonSerializerSettings = ctx.Resolve<JsonSerializerSettings>();
        
        restClient = new SimpleRestClient(httpClientFactory, "http://" + daemonEndpoints.First().Host.ToString() + ":" + daemonEndpoints.First().Port.ToString() + "/");
        rpc = new RpcClient(daemonEndpoints.First(), jsonSerializerSettings, messageBus, poolConfig.Id);

        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            // also setup wallet daemon
            walletRpc = new RpcClient(walletDaemonEndpoints.First(), jsonSerializerSettings, messageBus, poolConfig.Id);
        }
            // also setup poolservice
            poolserviceRpc = new RpcClient(poolserviceDaemonEndpoints.First(), jsonSerializerSettings, messageBus, poolConfig.Id);
    }

    protected override async Task<bool> AreDaemonsHealthyAsync(CancellationToken ct)
    {
        logger.Debug(() => "Checking if dynexd daemon is healthy...");
        
        // test daemons
        try
        {
            var response = await restClient.Get<GetInfoResponse>(DynexConstants.DaemonRpcGetInfoLocation, ct);
            if(response?.Status != "OK")
            {
                logger.Debug(() => $"dynexd daemon did not responded...");
                return false;
            }

            logger.Debug(() => $"{response?.Status} - Incoming: {response?.IncomingConnectionsCount} - Outgoing: {response?.OutgoingConnectionsCount})");
        }
        
        catch(Exception)
        {
            logger.Debug(() => $"dynexd daemon does not seem to be running...");
            return false;
        }
        
        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            logger.Debug(() => "Checking if walletd daemon is healthy...");
            
            // test wallet daemons
            var request2 = new GetBalanceRequest
            {
                Address = poolConfig.Address
            };

            var response2 = await walletRpc.ExecuteAsync<GetBalanceResponse>(logger, DynexWalletCommands.GetBalance, ct, request2);
            
            if(response2.Error != null)
                logger.Debug(() => $"walletd daemon response: {response2.Error.Message} (Code {response2.Error.Code})");

            return response2.Error == null;
        }

        return true;
    }

    protected override async Task<bool> AreDaemonsConnectedAsync(CancellationToken ct)
    {
        logger.Debug(() => "Checking if dynexd daemon is connected...");
        
        try
        {
            var response = await restClient.Get<GetInfoResponse>(DynexConstants.DaemonRpcGetInfoLocation, ct);

            if(response?.Status != "OK")
                logger.Debug(() => $"dynexd daemon is not connected...");

            if(response?.Status == "OK")
                logger.Debug(() => $"Peers connected - Incoming: {response?.IncomingConnectionsCount} - Outgoing: {response?.OutgoingConnectionsCount}");

            return response?.Status == "OK" &&
                (response?.OutgoingConnectionsCount + response?.IncomingConnectionsCount) > 0;
        }
        
        catch(Exception)
        {
            logger.Debug(() => $"dynexd daemon does not seem to be running...");
            return false;
        }
    }

    protected override async Task EnsureDaemonsSynchedAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        
        logger.Debug(() => "Checking if dynexd daemon is synched...");

        var syncPendingNotificationShown = false;

        do
        {
            var request = new GetBlockTemplateRequest
            {
                WalletAddress = poolConfig.Address,
                ReserveSize = DynexConstants.ReserveSize
            };

            var response = await rpc.ExecuteAsync<GetBlockTemplateResponse>(logger,
                DynexCommands.GetBlockTemplate, ct, request);
            
            if(response.Error != null)
                logger.Debug(() => $"dynexd daemon response: {response.Error.Message} (Code {response.Error.Code})");

            var isSynched = response.Error is not {Code: -9};

            if(isSynched)
            {
                logger.Info(() => "All daemons synched with blockchain");
                break;
            }

            if(!syncPendingNotificationShown)
            {
                logger.Info(() => "Daemon is still syncing with network. Manager will be started once synced.");
                syncPendingNotificationShown = true;
            }

            await ShowDaemonSyncProgressAsync(ct);
        } while(await timer.WaitForNextTickAsync(ct));
    }

    protected override async Task PostStartInitAsync(CancellationToken ct)
    {
        SetInstanceId();

        // coin config
        var coin = poolConfig.Template.As<DynexCoinTemplate>();
        
        try
        {
            var infoResponse = await restClient.Get<GetInfoResponse>(DynexConstants.DaemonRpcGetInfoLocation, ct);
        
            if(infoResponse?.Status != "OK")
                throw new PoolStartupException($"Init RPC failed...", poolConfig.Id);
        }
        
        catch(Exception)
        {
            logger.Debug(() => $"dynexd daemon does not seem to be running...");
            throw new PoolStartupException($"Init RPC failed...", poolConfig.Id);
        }
        
        // address validation
        poolAddressBase58Prefix = CryptonoteBindings.DecodeAddress(poolConfig.Address);
        if(poolAddressBase58Prefix == 0)
            throw new PoolStartupException("Unable to decode pool-address", poolConfig.Id);

        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            var addressResponse = await walletRpc.ExecuteAsync<GetAddressResponse>(logger, DynexWalletCommands.GetAddress, ct, new {});

            // ensure pool owns wallet
            //if(clusterConfig.PaymentProcessing?.Enabled == true && addressResponse.Response?.Address != poolConfig.Address)
            if(clusterConfig.PaymentProcessing?.Enabled == true && Exists(addressResponse.Response?.Address, element => element == poolConfig.Address) == false)
                throw new PoolStartupException($"Wallet-Daemon does not own pool-address '{poolConfig.Address}'", poolConfig.Id);
        }

        switch(networkType)
        {
            case DynexNetworkType.Main:
                if(poolAddressBase58Prefix != coin.AddressPrefix)
                    throw new PoolStartupException($"Invalid pool address prefix. Expected {coin.AddressPrefix}, got {poolAddressBase58Prefix}", poolConfig.Id);
                break;
            
            case DynexNetworkType.Test:
                if(poolAddressBase58Prefix != coin.AddressPrefixTestnet)
                    throw new PoolStartupException($"Invalid pool address prefix. Expected {coin.AddressPrefixTestnet}, got {poolAddressBase58Prefix}", poolConfig.Id);
                break;
        }

        // update stats
        BlockchainStats.RewardType = "POW";
        BlockchainStats.NetworkType = networkType.ToString();

        await UpdateNetworkStatsAsync(ct);

        // Periodically update network stats
        Observable.Interval(TimeSpan.FromMinutes(1))
            .Select(via => Observable.FromAsync(() =>
                Guard(()=> UpdateNetworkStatsAsync(ct),
                    ex=> logger.Error(ex))))
            .Concat()
            .Subscribe();

        SetupJobUpdates(ct);
    }

    private void SetInstanceId()
    {
        instanceId = new byte[DynexConstants.InstanceIdSize];

        using(var rng = RandomNumberGenerator.Create())
        {
            rng.GetNonZeroBytes(instanceId);
        }

        if(clusterConfig.InstanceId.HasValue)
            instanceId[0] = clusterConfig.InstanceId.Value;
    }

    protected virtual void SetupJobUpdates(CancellationToken ct)
    {
        var blockSubmission = blockFoundSubject.Synchronize();
        var pollTimerRestart = blockFoundSubject.Synchronize();

        var triggers = new List<IObservable<(string Via, string Data)>>
        {
            blockSubmission.Select(x => (JobRefreshBy.BlockFound, (string) null))
        };

        if(extraPoolConfig?.BtStream == null)
        {
            // collect ports
            var zmq = poolConfig.Daemons
                .Where(x => !string.IsNullOrEmpty(x.Extra.SafeExtensionDataAs<DynexDaemonEndpointConfigExtra>()?.ZmqBlockNotifySocket))
                .ToDictionary(x => x, x =>
                {
                    var extra = x.Extra.SafeExtensionDataAs<DynexDaemonEndpointConfigExtra>();
                    var topic = !string.IsNullOrEmpty(extra.ZmqBlockNotifyTopic.Trim()) ? extra.ZmqBlockNotifyTopic.Trim() : BitcoinConstants.ZmqPublisherTopicBlockHash;

                    return (Socket: extra.ZmqBlockNotifySocket, Topic: topic);
                });

            if(zmq.Count > 0)
            {
                logger.Info(() => $"Subscribing to ZMQ push-updates from {string.Join(", ", zmq.Values)}");

                var blockNotify = rpc.ZmqSubscribe(logger, ct, zmq)
                    .Where(msg =>
                    {
                        bool result = false;

                        try
                        {
                            var text = Encoding.UTF8.GetString(msg[0].Read());

                            result = text.StartsWith("json-minimal-chain_main:");
                        }

                        catch
                        {
                        }

                        if(!result)
                            msg.Dispose();

                        return result;
                    })
                    .Select(msg =>
                    {
                        using(msg)
                        {
                            var token = GetFrameAsJToken(msg[0].Read());

                            if (token != null)
                                return token.Value<long>("first_height").ToString(CultureInfo.InvariantCulture);

                            // We just take the second frame's raw data and turn it into a hex string.
                            // If that string changes, we got an update (DistinctUntilChanged)
                            return msg[0].Read().ToHexString();
                        }
                    })
                    .DistinctUntilChanged()
                    .Select(_ => (JobRefreshBy.PubSub, (string) null))
                    .Publish()
                    .RefCount();

                pollTimerRestart = Observable.Merge(
                        blockSubmission,
                        blockNotify.Select(_ => Unit.Default))
                    .Publish()
                    .RefCount();

                triggers.Add(blockNotify);
            }

            if(poolConfig.BlockRefreshInterval > 0)
            {
                // periodically update block-template
                var pollingInterval = poolConfig.BlockRefreshInterval > 0 ? poolConfig.BlockRefreshInterval : 1000;

                triggers.Add(Observable.Timer(TimeSpan.FromMilliseconds(pollingInterval))
                    .TakeUntil(pollTimerRestart)
                    .Select(_ => (JobRefreshBy.Poll, (string) null))
                    .Repeat());
            }

            else
            {
                // get initial blocktemplate
                triggers.Add(Observable.Interval(TimeSpan.FromMilliseconds(1000))
                    .Select(_ => (JobRefreshBy.Initial, (string) null))
                    .TakeWhile(_ => !hasInitialBlockTemplate));
            }
        }

        else
        {
            triggers.Add(BtStreamSubscribe(extraPoolConfig.BtStream)
                .Select(json => (JobRefreshBy.BlockTemplateStream, json))
                .Publish()
                .RefCount());

            // get initial blocktemplate
            triggers.Add(Observable.Interval(TimeSpan.FromMilliseconds(1000))
                .Select(_ => (JobRefreshBy.Initial, (string) null))
                .TakeWhile(_ => !hasInitialBlockTemplate));
        }

        Blocks = triggers.Merge()
            .Select(x => Observable.FromAsync(() => UpdateJob(ct, x.Via, x.Data)))
            .Concat()
            .Where(isNew => isNew)
            .Do(_ => hasInitialBlockTemplate = true)
            .Select(_ => Unit.Default)
            .Publish()
            .RefCount();
    }

    #endregion // Overrides
}
