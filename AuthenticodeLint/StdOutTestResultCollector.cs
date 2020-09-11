using AuthenticodeLinter.Tests;
using System;
using System.Collections.Generic;

namespace AuthenticodeLinter
{
    public class StdOutTestResultCollector : ITestResultCollector
    {
        private string _setName;

        public void BeginSet(string setName)
        {
            _setName = setName;
            Console.Out.WriteLine($"Start checks for {_setName}.");
        }

        public void CollectResult(IAuthenticodeTest test, TestResult result, IReadOnlyList<string> additionalOutput, Boolean dontInsertRulesTable, string appID, string fileName, string signatureHash, string thumbprint, string portal)
        {
            int testID = test.Test;
            string testName = test.TestName;
            string testResult = "";
            if (_setName == null)
            {
                throw new InvalidOperationException("Cannot collect results for an unknown set.");
            }

            switch (result)
            {
                case TestResult.Skip:
                    Console.Out.WriteLine($"\tTest #{test.Test} \"{test.TestName}\" was skipped because it was suppressed.");
                    testResult = "skip";
                    break;
                case TestResult.Excluded:
                    Console.Out.WriteLine($"\tTest #{test.Test} \"{test.TestName}\" was excluded because it is not part of the testset.");
                    testResult = "excluded";
                    break;
                case TestResult.Fail:
                    Console.Out.WriteLine($"\tTest #{test.Test} \"{test.TestName}\" failed.");
                    testResult = "fail";
                    break;
                case TestResult.Pass:
                    Console.Out.WriteLine($"\tTest #{test.Test} \"{test.TestName}\" passed.");
                    testResult = "pass";
                    break;
            }
            if(!dontInsertRulesTable)
                DBConnect.InsertRulsTable(testID, testName, testResult, appID, fileName, signatureHash, thumbprint, portal);
            foreach (var message in additionalOutput)
            {
                Console.Out.WriteLine("\t\t" + message);
            }
        }

        public void CompleteSet()
        {
            Console.Out.WriteLine($"Complete checks for {_setName}.");
            _setName = null;
        }

        public void Flush()
        {
        }
    }
}
