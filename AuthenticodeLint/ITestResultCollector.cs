using AuthenticodeLinter.Tests;
using System;
using System.Collections.Generic;

namespace AuthenticodeLinter
{
    public interface ITestResultCollector
    {
        void CollectResult(IAuthenticodeTest test, TestResult result, IReadOnlyList<string> additionalOutput, Boolean dontInsertRulesTable, string appID, string fileName, string signatureHash, string thumbprint, string portal);
        void BeginSet(string setName);
        void CompleteSet();
        void Flush();
    }
}
