using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using _Script.Data;
using _Script.State;
using Libplanet;
using UnityEngine;
using UnityEngine.UI;

namespace _Script
{
    public class Game : MonoBehaviour
    {
        public Text timerText;
        public Text countText;
        public Text addressText;
        public Text rankingText;
        public Click click;
        public ScrollRect rankingBoard;
        public RankingRow rankingRow;
        private float _time;
        private long _totalCount = 0;
        private Table<Level> _levelTable;
        private Dictionary<Address, int> _attacks = new Dictionary<Address, int>();

        private void Awake()
        {
            Screen.SetResolution(1024, 768, FullScreenMode.Windowed);
            Application.SetStackTraceLogType(LogType.Log, StackTraceLogType.None);
            AgentController.Initialize();
            var hex = AgentController.Agent.Address.ToHex().Substring(0, 4);
            addressText.text = $"Address: {hex}";
            _time = Agent.TxProcessInterval;
            SetTimer(_time);
            _levelTable = new Table<Level>();
            _levelTable.Load(Resources.Load<TextAsset>("level").text);
            StartCoroutine(GetTotalCount());
            StartCoroutine(GetRankingState());
        }

        private void SetTimer(float time)
        {
            timerText.text = Mathf.Ceil(time).ToString(CultureInfo.CurrentCulture);
        }

        private void ResetTimer()
        {
            SetTimer(0);
            click.ResetCount();
        }

        private void FixedUpdate()
        {
            if (_time > 0)
            {
                _time -= Time.deltaTime;
                SetTimer(_time);
            }
            else
            {
                _time = Agent.TxProcessInterval;
                var actions = new List<ActionBase>();
                if (click._count > 0)
                {
                    var action = new AddCount(click._count);
                    actions.Add(action);
                }

                actions.AddRange(_attacks.Select(pair => new SubCount(pair.Key, pair.Value)));
                if (actions.Any())
                {
                    AgentController.Agent.MakeTransaction(actions);
                }
                _attacks = new Dictionary<Address, int>();

                ResetTimer();
            }
        }

        private void UpdateTotalCount(long count)
        {
            _totalCount = count;
            var selected = _levelTable.Values.FirstOrDefault(i => i.exp > _totalCount) ?? _levelTable.Values.Last();
            click.Set(selected.id);
            countText.text = _totalCount.ToString();
        }

        private IEnumerator GetTotalCount()
        {
            while (true)
            {
                var count = (long?) AgentController.Agent.GetState(AgentController.Agent.Address) ?? 0;
                UpdateTotalCount(count);
                yield return new WaitForSeconds(1f);
            }
        }

        private IEnumerator GetRankingState()
        {
            while (true)
            {
                var rankingState = (RankingState) AgentController.Agent.GetState(RankingState.Address) ?? new RankingState();
                yield return UpdateRankingBoard(rankingState);
                yield return new WaitForSeconds(10f);
            }
        }

        private IEnumerator UpdateRankingBoard(RankingState rankingState)
        {
            foreach (Transform child in rankingBoard.content.transform)
            {
                Destroy(child.gameObject);
            }
            yield return new WaitForEndOfFrame();

            rankingRow.gameObject.SetActive(true);
            var ranking = rankingState.GetRanking().ToList();
            for (var i = 0; i < ranking.Count; i++)
            {
                var rankingInfo = ranking[i];
                var go = Instantiate(rankingRow, rankingBoard.content.transform);
                var row = go.GetComponent<RankingRow>();
                var rank = i + 1;
                row.Set(rank, rankingInfo);
                if (rankingInfo.Address == AgentController.Agent.Address)
                {
                    rankingText.text = $"My Ranking: {rank}";
                }
            }

            rankingRow.gameObject.SetActive(false);
            yield return null;
        }

        public void Attack(RankingRow row)
        {
            var address = row.address;
            if (_attacks.TryGetValue(address, out _))
            {
                _attacks[address] += 1;
            }
            else
            {
                _attacks[address] = 0;
            }
        }
    }
}
