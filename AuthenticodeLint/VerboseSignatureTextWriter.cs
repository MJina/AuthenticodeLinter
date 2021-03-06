﻿using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter
{
    public class MemorySignatureLogger : SignatureLogger
    {
        public override void LogMessage(string message) => Messages.Add(message);

        public override void LogSignatureMessage(ICmsSignature signature, string message)
        {
            var digestString = HashHelpers.GetHashForSignature(signature);
            Messages.Add($"Signature {digestString}: {message}");
        }
    }

    public class NullSignatureLogger : SignatureLogger
    {
        public override void LogMessage(string message)
        {
        }

        public override void LogSignatureMessage(ICmsSignature signature, string message)
        {
        }
    }

    public abstract class SignatureLogger
    {
        public static SignatureLogger Null { get; } = new NullSignatureLogger();

        public List<string> Messages { get; } = new List<string>();

        public abstract void LogSignatureMessage(ICmsSignature signature, string message);
        public abstract void LogMessage(string message);
    }
}
