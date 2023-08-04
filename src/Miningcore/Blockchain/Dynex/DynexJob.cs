using System.Text;
using Miningcore.Blockchain.Dynex.DaemonResponses;
using Miningcore.Blockchain.Dynex.DaemonRequests;
using Miningcore.Blockchain.Dynex.StratumRequests;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.Native;
using Miningcore.Stratum;
using Miningcore.Util;
using Miningcore.Rest;
using Miningcore.Rpc;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using static Miningcore.Native.Cryptonight.Algorithm;
using Contract = Miningcore.Contracts.Contract;
using NLog;
using static Miningcore.Util.ActionUtils;

namespace Miningcore.Blockchain.Dynex;

public class DynexJob
{
    public DynexJob(GetBlockTemplateResponse blockTemplate, byte[] instanceId, string jobId,
        DynexCoinTemplate coin, PoolConfig poolConfig, ClusterConfig clusterConfig, string prevHash)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(poolConfig);
        Contract.RequiresNonNull(clusterConfig);
        Contract.RequiresNonNull(instanceId);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));
        BlockTemplate = blockTemplate;
        PrepareBlobTemplate(instanceId);
        PrevHash = prevHash;
    }

    protected ILogger logger;
    private byte[] blobTemplate;
    private int extraNonce;

    private void PrepareBlobTemplate(byte[] instanceId)
    {
        blobTemplate = BlockTemplate.Blob.HexToByteArray();

        // inject instanceId
        instanceId.CopyTo(blobTemplate, BlockTemplate.ReservedOffset + DynexConstants.ExtraNonceSize);
    }
   
    private string EncodeBlob(uint workerExtraNonce)
    {
        Span<byte> blob = stackalloc byte[blobTemplate.Length];
        blobTemplate.CopyTo(blob);

        // inject extranonce (big-endian) at the beginning of the reserved area
        var bytes = BitConverter.GetBytes(workerExtraNonce.ToBigEndian());
        bytes.CopyTo(blob[BlockTemplate.ReservedOffset..]);

        return CryptonoteBindings.ConvertBlob(blob, blobTemplate.Length).ToHexString();
    }

    private string EncodeTarget(double difficulty, int size = 4)
    {
        var diff = BigInteger.ValueOf((long) (difficulty * 255d));
        var quotient = DynexConstants.Diff1.Divide(diff).Multiply(BigInteger.ValueOf(255));
        var bytes = quotient.ToByteArray().AsSpan();
        Span<byte> padded = stackalloc byte[32];

        var padLength = padded.Length - bytes.Length;

        if(padLength > 0)
            bytes.CopyTo(padded.Slice(padLength, bytes.Length));

        padded = padded[..size];
        padded.Reverse();

        return padded.ToHexString();
    }

    private void ComputeBlockHash(ReadOnlySpan<byte> blobConverted, Span<byte> result)
    {
        // blockhash is computed from the converted blob data prefixed with its length
        Span<byte> block = stackalloc byte[blobConverted.Length + 1];
        block[0] = (byte) blobConverted.Length;
        blobConverted.CopyTo(block[1..]);

        CryptonoteBindings.CryptonightHashFast(block, result);
    }

    #region API-Surface

    public string PrevHash { get; }
    public GetBlockTemplateResponse BlockTemplate { get; }

    public void PrepareWorkerJob(DynexWorkerJob workerJob, out string blob, out string target)
    {
        workerJob.Height = BlockTemplate.Height;
        workerJob.ExtraNonce = (uint) Interlocked.Increment(ref extraNonce);

        if(extraNonce < 0)
            extraNonce = 0;

        blob = EncodeBlob(workerJob.ExtraNonce);
        target = EncodeTarget(workerJob.Difficulty);
    }

    public (byte[] convertedBlob, string found_hash, double shareDiff, double stratumDifficulty, string pouw_data, string algo, string BlobHex) PreProcessShare(string nonce, uint workerExtraNonce, DynexSubmitShareRequest workerHash, StratumConnection worker)
    {
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(workerHash.Result));
        Contract.Requires<ArgumentException>(workerExtraNonce != 0);

        var context = worker.ContextAs<DynexWorkerContext>();

        // clone template
        Span<byte> blob = stackalloc byte[blobTemplate.Length];
        blobTemplate.CopyTo(blob);

        // inject extranonce
        var bytes = BitConverter.GetBytes(workerExtraNonce.ToBigEndian());
        bytes.CopyTo(blob[BlockTemplate.ReservedOffset..]);

        // inject nonce
        bytes = nonce.HexToByteArray();
        bytes.CopyTo(blob[DynexConstants.BlobNonceOffset..]);

        // convert
        var blobConverted = CryptonoteBindings.ConvertBlob(blob, blobTemplate.Length);
        if(blobConverted == null)
            throw new StratumException(StratumError.MinusOne, "malformed blob");

        // extract values
        string found_hash = workerHash.Result;
        string algo = workerHash.Algorithm;
        string mallob = workerHash.Mallob;
        string pouw_data = workerHash.PouwData;
        byte[] hashBytes = Hex.Decode(found_hash);
        BigInteger hashBigInt = new BigInteger(hashBytes);

        if(algo != "dynexsolve224final" && algo != "dynexsolve230")
           throw new StratumException(StratumError.MinusOne, "Incorrect algo");

        // check difficulty
        var headerValue = new System.Numerics.BigInteger(hashBigInt.ToByteArray());
        var shareDiff = (double)new BigRational(DynexConstants.Diff1b, headerValue);
        var stratumDifficulty = context.Difficulty;
        CancellationTokenSource cts = new CancellationTokenSource();
        CancellationToken ct = cts.Token;


        return (blobConverted, found_hash, shareDiff, stratumDifficulty, pouw_data, algo, blob.ToHexString());
    }

    public (Share Share, string BlobHex) ProcessShare(string nonce, uint workerExtraNonce, DynexSubmitShareRequest workerHash, StratumConnection worker)
    {
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(workerHash.Result));
        Contract.Requires<ArgumentException>(workerExtraNonce != 0);

        var context = worker.ContextAs<DynexWorkerContext>();

        // validate nonce
        if(!DynexConstants.RegexValidNonce.IsMatch(nonce))
            throw new StratumException(StratumError.MinusOne, "malformed nonce");

        // clone template
        Span<byte> blob = stackalloc byte[blobTemplate.Length];
        blobTemplate.CopyTo(blob);

        // inject extranonce
        var bytes = BitConverter.GetBytes(workerExtraNonce.ToBigEndian());
        bytes.CopyTo(blob[BlockTemplate.ReservedOffset..]);

        // inject nonce
        bytes = nonce.HexToByteArray();
        bytes.CopyTo(blob[DynexConstants.BlobNonceOffset..]);

        // convert
        var blobConverted = CryptonoteBindings.ConvertBlob(blob, blobTemplate.Length);
        if(blobConverted == null)
            throw new StratumException(StratumError.MinusOne, "malformed blob");

        // hash it
        // Span<byte> headerHash = stackalloc byte[32];
        // hashFunc(blobConverted, headerHash, BlockTemplate.Height);

        // var headerHashString = headerHash.ToHexString();
        // if(headerHashString != workerHash)
        //   throw new StratumException(StratumError.MinusOne, "bad hash");

        // extract values
        string found_hash = workerHash.Result;
        string algo = workerHash.Algorithm;
        string mallob = workerHash.Mallob;
        string pouw_data = workerHash.PouwData;
        byte[] hashBytes = Hex.Decode(found_hash);
        BigInteger hashBigInt = new BigInteger(hashBytes);

        // check difficulty
        var headerValue = new System.Numerics.BigInteger(hashBigInt.ToByteArray());
        var shareDiff = (double)new BigRational(DynexConstants.Diff1b, headerValue);
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;
        var isBlockCandidate = shareDiff >= BlockTemplate.Difficulty;

        CancellationTokenSource cts = new CancellationTokenSource();
        CancellationToken ct = cts.Token;

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;
                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        var result = new Share
        {
            BlockHeight = BlockTemplate.Height,
            Difficulty = stratumDifficulty,
        };

        if(isBlockCandidate)
        {
            // Compute block hash
            Span<byte> blockHash = stackalloc byte[32];
            ComputeBlockHash(blobConverted, blockHash);

            // Fill in block-relevant fields
            result.IsBlockCandidate = true;
            result.BlockHash = blockHash.ToHexString();
        }

        return (result, blob.ToHexString());
    }
    #endregion // API-Surface
}
