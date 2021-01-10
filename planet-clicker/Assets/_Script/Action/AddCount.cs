using _Script.State;
using Bencodex.Types;
using Libplanet;
using Libplanet.Action;
using LibplanetUnity;
using LibplanetUnity.Action;
using UnityEngine;

namespace _Script.Action
{
    [ActionType("add_count")]
    public class AddCount : ActionBase
    {
        private long _count;

        public AddCount()
        {
        }

        public AddCount(long count)
        {
            _count = count;
        }

        public override IValue PlainValue =>
            Bencodex.Types.Dictionary.Empty.SetItem("count", _count);

        public override void LoadPlainValue(IValue plainValue)
        {
            var serialized = (Bencodex.Types.Dictionary)plainValue;
            _count = (long)((Integer)serialized["count"]).Value;
        }

        public override IAccountStateDelta Execute(IActionContext ctx)
        {
            var states = ctx.PreviousStates;
            var rankingAddress = RankingState.Address;
            states.TryGetState(default, out Bencodex.Types.Integer currentCount);
            var nextCount = currentCount + _count;

            Debug.Log($"add_count: CurrentCount: {currentCount}, NextCount: {nextCount}");

            if (!states.TryGetState(rankingAddress, out Bencodex.Types.Dictionary rankingState))
            {
                rankingState = new Dictionary();
            }
            rankingState = rankingState.SetItem(default(Address).ToByteArray(), nextCount);
            states = states.SetState(rankingAddress, rankingState);
            return states.SetState(default, (Bencodex.Types.Integer)nextCount);
        }
    }
}
