using System.Collections.Generic;
using AuthenticodeLinter.Tests;
using System;
using System.Linq;
using AuthenticodeExaminer;
using System.IO;

namespace AuthenticodeLinter
{
    public class CheckEngine
    {
        static CheckEngine()
        {
            Instance = new CheckEngine();
        }

        public static CheckEngine Instance { get; }

        public IReadOnlyList<IAuthenticodeTest> GetTests()
        {
            return (from type in typeof(IAuthenticodeTest).Assembly.GetExportedTypes()
                    where typeof(IAuthenticodeTest).IsAssignableFrom(type) && type.GetConstructor(Type.EmptyTypes) != null
                    let instance = (IAuthenticodeTest)Activator.CreateInstance(type)
                    orderby instance.Test
                    select instance
                    ).ToList();
        }

        public TestEngineResult RunAllTests(string file, IReadOnlyList<ICmsSignature> signatures, List<ITestResultCollector> collectors, CheckConfiguration configuration)
        {
            var verbose = configuration.Verbose;
            var suppressedTestIDs = configuration.SuppressErrorIDs;
            var tests = GetTests();
            var engineResult = TestEngineResult.AllPass;
            collectors.ForEach(c => c.BeginSet(file));
            Boolean dontInsertRulesTable = false;
            string portal = "";
            var digestStr = "";
            string appID = "";
            string fileName = "";
            string thumbprint = "";

            foreach (var test in tests)
            {
                TestResult result;
                var verboseWriter = verbose ? new MemorySignatureLogger() : SignatureLogger.Null;
                if (signatures.Count == 0)
                {
                    result = TestResult.Fail;
                    verboseWriter.LogMessage("File is not Authenticode signed.");
                    dontInsertRulesTable = true;
                }
                else
                {
                    if (suppressedTestIDs.Contains(test.Test))
                    {
                        result = TestResult.Skip;
                    }
                    else if ((test.TestSet & configuration.TestSet) == 0)
                    {
                        result = TestResult.Excluded;
                    }
                    else
                    {
                        switch (test)
                        {
                            case IAuthenticodeFileTest fileTest:
                                result = fileTest.Validate(file, verboseWriter, configuration);
                                break;
                            case IAuthenticodeSignatureTest sigTest:
                                result = sigTest.Validate(signatures, verboseWriter, configuration);
                                break;
                            default:
                                throw new NotSupportedException("Test type is not supported.");
                        }
                    }
                }
                if (result == TestResult.Fail)
                {
                    engineResult = TestEngineResult.NotAllPass;
                }
                if(!dontInsertRulesTable)
                {
                    digestStr = HashHelpers.GetHashForSignature(signatures[0]);//message digest of siganture(signature->details->advance->msg digest)

                    appID = Program.fileName;
                    fileName = Program.fileName;
                    portal = Program.portalName;
                    thumbprint = signatures[0].Certificate.Thumbprint;

                }
                collectors.ForEach(c => c.CollectResult(test, result, verboseWriter.Messages, dontInsertRulesTable, appID, fileName, digestStr, thumbprint, portal));
            }
            if (configuration.ExtractPath != null)
            {
                Extraction.ExtractToDisk(file, configuration, signatures);
            }
            collectors.ForEach(c => c.CompleteSet());
            return engineResult;
        }
    }

    public enum TestEngineResult
    {
        AllPass,
        NotAllPass
    }
}
