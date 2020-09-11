using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class NoWeakFileDigestAlgorithmsTest : IAuthenticodeSignatureTest
    {
        public int Test => 10002;

        public string TestName => "No Weak Digest Algorithms";

        public string ShortDescription => "Checks for weak digest algorithms.";

        public TestSet TestSet => TestSet.All;
        
        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
            var result = TestResult.Pass;
            foreach(var signature in signatures)
            {               
                if (signature.DigestAlgorithm.Value == KnownOids.MD2)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.MD2)} digest algorithm.");
                    result = TestResult.Fail;
                }
                else if (signature.DigestAlgorithm.Value == KnownOids.MD4)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.MD4)} digest algorithm.");
                    result = TestResult.Fail;
                }
                else if (signature.DigestAlgorithm.Value == KnownOids.MD5)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Uses the {nameof(KnownOids.MD5)} digest algorithm.");
                    result = TestResult.Fail;
                }
            }
            return result;
        }
    }
}
