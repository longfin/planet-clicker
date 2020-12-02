using Serilog.Core;
using Serilog.Events;

namespace LibplanetUnity
{
    internal class UnityDebugSink : ILogEventSink
    {
        public void Emit(LogEvent logEvent)
        {
            if (logEvent.Exception is null)
            {
                UnityEngine.Debug.Log($"{logEvent.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")}: {logEvent.RenderMessage()}");
            }
            else
            {
                UnityEngine.Debug.Log($"{logEvent.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")}: {logEvent.RenderMessage()}\n{logEvent.Exception}");
            }
        }
    }

}