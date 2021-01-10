using System;
using System.Runtime.Serialization;

namespace LibplanetUnity
{
    [Serializable]
    internal class InvalidBlockMinerException : Exception
    {
        public InvalidBlockMinerException()
        {
        }

        public InvalidBlockMinerException(string message) : base(message)
        {
        }

        public InvalidBlockMinerException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidBlockMinerException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}