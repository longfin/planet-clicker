﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AsyncIO;
using Libplanet;
using Libplanet.Action;
using Libplanet.Blockchain;
using Libplanet.Blockchain.Policies;
using Libplanet.Blocks;
using Libplanet.Crypto;
using Libplanet.Net;
using Libplanet.Store;
using Libplanet.Tx;
using UnityEngine;

namespace _Script
{
    /// <summary>
    /// 메인넷에 직접 붙어서 블록을 마이닝 한다.
    /// </summary>
    public class Agent : IDisposable
    {
        private class DebugPolicy : IBlockPolicy<PolymorphicAction<ActionBase>>
        {
            public DebugPolicy()
            {
            }

            public IAction BlockAction { get; }

            public InvalidBlockException ValidateNextBlock(IReadOnlyList<Block<PolymorphicAction<ActionBase>>> blocks, Block<PolymorphicAction<ActionBase>> nextBlock)
            {
                return null;
            }

            public long GetNextBlockDifficulty(IReadOnlyList<Block<PolymorphicAction<ActionBase>>> blocks)
            {
                Thread.Sleep(SleepInterval);
                return blocks.Any() ? 1 : 0;
            }
        }

        public const float TxProcessInterval = 3.0f;
        private const int SwarmDialTimeout = 5000;
        private const int SwarmLinger = 1 * 1000;

        private static readonly TimeSpan BlockInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan SleepInterval = TimeSpan.FromSeconds(3);

        protected readonly BlockChain<PolymorphicAction<ActionBase>> _blocks;
        private readonly Swarm<PolymorphicAction<ActionBase>> _swarm;
        protected LiteDBStore _store;
        private readonly ImmutableList<Peer> _seedPeers;
        private readonly IImmutableSet<Address> _trustedPeers;

        private readonly CancellationTokenSource _cancellationTokenSource;

        public IDictionary<TxId, Transaction<PolymorphicAction<ActionBase>>> Transactions => _blocks.Transactions;
        public IBlockPolicy<PolymorphicAction<ActionBase>> Policy => _blocks.Policy;
        public long BlockIndex => _blocks?.Tip?.Index ?? 0;

        public LiteDBStore Store => _store;

        public PrivateKey PrivateKey { get; }
        public Address Address { get; }

        public event EventHandler BootstrapStarted;
        public event EventHandler PreloadStarted;
        public event EventHandler<PreloadState> PreloadProcessed;
        public event EventHandler PreloadEnded;

        public bool SyncSucceed { get; private set; }


        static Agent()
        {
            ForceDotNet.Force();
        }

        public Agent(
            PrivateKey privateKey,
            string path,
            IEnumerable<Peer> peers,
            IEnumerable<IceServer> iceServers,
            string host,
            int? port)
        {
            Debug.Log(path);
            var policy = GetPolicy();
            PrivateKey = privateKey;
            Address = privateKey.PublicKey.ToAddress();
            _store = new LiteDBStore($"{path}.ldb", flush: false);
            _blocks = new BlockChain<PolymorphicAction<ActionBase>>(policy, _store);
#if BLOCK_LOG_USE
            FileHelper.WriteAllText("Block.log", "");
#endif

            _swarm = new Swarm<PolymorphicAction<ActionBase>>(
                _blocks,
                privateKey,
                appProtocolVersion: 1,
                millisecondsDialTimeout: SwarmDialTimeout,
                millisecondsLinger: SwarmLinger,
                host: host,
                listenPort: port,
                iceServers: iceServers,
                differentVersionPeerEncountered: DifferentAppProtocolVersionPeerEncountered);

            _seedPeers = peers.Where(peer => peer.PublicKey != privateKey.PublicKey).ToImmutableList();
            // Init SyncSucceed
            SyncSucceed = true;

            // FIXME: Trusted peers should be configurable
            _trustedPeers = _seedPeers.Select(peer => peer.Address).ToImmutableHashSet();
            _cancellationTokenSource = new CancellationTokenSource();
        }

        private void DifferentAppProtocolVersionPeerEncountered(object sender, DifferentProtocolVersionEventArgs e)
        {
            Debug.LogWarningFormat("Different Version Encountered Expected: {0} Actual : {1}",
                e.ExpectedVersion, e.ActualVersion);
            SyncSucceed = false;
        }

        public void Dispose()
        {
            _cancellationTokenSource.Cancel();
            // `_swarm`의 내부 큐가 비워진 다음 완전히 종료할 때까지 더 기다립니다.
            Task.Run(async () => await _swarm?.StopAsync()).ContinueWith(_ =>
            {
                _store?.Dispose();
            }).Wait(SwarmLinger + 1 * 1000);
        }

        public IEnumerator CoSwarmRunner()
        {
            BootstrapStarted?.Invoke(this, null);
            var bootstrapTask = Task.Run(async () =>
            {
                try
                {
                    await _swarm.BootstrapAsync(
                        _seedPeers,
                        5000,
                        5000,
                        _cancellationTokenSource.Token);
                }
                catch (Exception e)
                {
                    Debug.LogFormat("Exception occurred during bootstrap {0}", e);
                }
            });

            yield return new WaitUntil(() => bootstrapTask.IsCompleted);

            PreloadStarted?.Invoke(this, null);
            Debug.Log("PreloadingStarted event was invoked");

            DateTimeOffset started = DateTimeOffset.UtcNow;
            long existingBlocks = _blocks?.Tip?.Index ?? 0;
            Debug.Log("Preloading starts");

            // _swarm.PreloadAsync() 에서 대기가 발생하기 때문에
            // 이를 다른 스레드에서 실행하여 우회하기 위해 Task로 감쌉니다.
            var swarmPreloadTask = Task.Run(async () =>
            {
                await _swarm.PreloadAsync(
                    new Progress<PreloadState>(state =>
                        PreloadProcessed?.Invoke(this, state)
                    ),
                    trustedStateValidators: _trustedPeers,
                    cancellationToken: _cancellationTokenSource.Token
                );
            });

            yield return new WaitUntil(() => swarmPreloadTask.IsCompleted);
            DateTimeOffset ended = DateTimeOffset.UtcNow;

            if (swarmPreloadTask.Exception is Exception exc)
            {
                Debug.LogErrorFormat(
                    "Preloading terminated with an exception: {0}",
                    exc
                );
                throw exc;
            }

            var index = _blocks?.Tip?.Index ?? 0;
            Debug.LogFormat(
                "Preloading finished; elapsed time: {0}; blocks: {1}",
                ended - started,
                index - existingBlocks
            );


            PreloadEnded?.Invoke(this, null);

            var swarmStartTask = Task.Run(async () =>
            {
                try
                {
                    await _swarm.StartAsync();
                }
                catch (TaskCanceledException)
                {
                }
                catch (Exception e)
                {
                    Debug.LogErrorFormat(
                        "Swarm terminated with an exception: {0}",
                        e
                    );
                    throw;
                }
            });

            Task.Run(async () =>
            {
                await _swarm.WaitForRunningAsync();

                Debug.LogFormat(
                    "The address of this node: {0},{1},{2}",
                    ByteUtil.Hex(PrivateKey.PublicKey.Format(true)),
                    _swarm.EndPoint.Host,
                    _swarm.EndPoint.Port
                );
            });

            yield return new WaitUntil(() => swarmStartTask.IsCompleted);
        }

        public IEnumerator CoMiner()
        {
            while (true)
            {
                var txs = new HashSet<Transaction<PolymorphicAction<ActionBase>>>();

                var task = Task.Run(() =>
                {
                    var block = _blocks.MineBlock(Address);
                    _swarm.BroadcastBlocks(new[] {block});
                    return block;
                });
                yield return new WaitUntil(() => task.IsCompleted);

                if (!task.IsCanceled && !task.IsFaulted)
                {
                    var block = task.Result;
                    Debug.Log($"created block index: {block.Index}, difficulty: {block.Difficulty}");
#if BLOCK_LOG_USE
                    FileHelper.AppendAllText("Block.log", task.Result.ToVerboseString());
#endif
                }
                else
                {
                    var invalidTxs = txs;
                    var retryActions = new HashSet<IImmutableList<PolymorphicAction<ActionBase>>>();

                    if (task.IsFaulted)
                    {
                        foreach (var ex in task.Exception.InnerExceptions)
                        {
                            if (ex is InvalidTxNonceException invalidTxNonceException)
                            {
                                var invalidNonceTx = _blocks.Transactions[invalidTxNonceException.TxId];

                                if (invalidNonceTx.Signer == Address)
                                {
                                    Debug.Log($"Tx[{invalidTxNonceException.TxId}] nonce is invalid. Retry it.");
                                    retryActions.Add(invalidNonceTx.Actions);
                                }
                            }

                            if (ex is InvalidTxException invalidTxException)
                            {
                                Debug.Log($"Tx[{invalidTxException.TxId}] is invalid. mark to unstage.");
                                invalidTxs.Add(_blocks.Transactions[invalidTxException.TxId]);
                            }

                            Debug.LogException(ex);
                        }
                    }
                    _blocks.UnstageTransactions(invalidTxs);

                    foreach (var retryAction in retryActions)
                    {
                        MakeTransaction(retryAction, true);
                    }
                }
            }
        }

        public void MakeTransaction(IEnumerable<ActionBase> gameActions)
        {
            var actions = gameActions.Select(gameAction => (PolymorphicAction<ActionBase>) gameAction).ToList();
            Task.Run(() => MakeTransaction(actions, true));
        }


        public object GetState(Address address)
        {
            AddressStateMap states = _blocks.GetStates(new[] {address});
            states.TryGetValue(address, out object value);
            return value;
        }

        private IBlockPolicy<PolymorphicAction<ActionBase>> GetPolicy()
        {
# if UNITY_EDITOR
            return new DebugPolicy();
# else
            return new BlockPolicy<PolymorphicAction<ActionBase>>(
                null,
                BlockInterval,
                100000,
                2048
            );
#endif
        }

        public void AppendBlock(Block<PolymorphicAction<ActionBase>> block)
        {
            _blocks.Append(block);
        }

        private Transaction<PolymorphicAction<ActionBase>> MakeTransaction(
            IEnumerable<PolymorphicAction<ActionBase>> actions, bool broadcast)
        {
            var polymorphicActions = actions.ToArray();
            Debug.LogFormat("Make Transaction with Actions: `{0}`",
                string.Join(",", polymorphicActions.Select(i => i.InnerAction)));
            return _blocks.MakeTransaction(PrivateKey, polymorphicActions, broadcast: broadcast);
        }
    }
}
