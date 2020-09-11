using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class SecurePrimarySignatureTest : IAuthenticodeSignatureTest
    {
        public int Test => 10000;

        public string TestName => "Primary Digest Algorithm";

        public string ShortDescription => "Check if the primary digest algorithm is secure enough.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            if (graph.Count == 0)
            {
                return TestResult.Fail;
            }
            var primary = graph[0];
            if (primary.DigestAlgorithm.Value == KnownOids.SHA1 || 
                primary.DigestAlgorithm.Value == KnownOids.MD2  ||
                primary.DigestAlgorithm.Value == KnownOids.MD4  ||
                primary.DigestAlgorithm.Value == KnownOids.MD5 )
            {
                verboseWriter.LogSignatureMessage(primary, $"Expected {nameof(KnownOids.SHA256)} digest algorithm but is {primary.DigestAlgorithm.FriendlyName}.");
                return TestResult.Fail;
            }
            return TestResult.Pass;
        }
    }
}
