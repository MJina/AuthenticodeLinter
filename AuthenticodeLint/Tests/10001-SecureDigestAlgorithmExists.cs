using System.Collections.Generic;
using System.Linq;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class SecureDigestSignatureExistsTest : IAuthenticodeSignatureTest
    {
        public int Test => 10001;

        public string TestName => "Secure Digest Algorithm";

        public string ShortDescription => "Check for a dual signature: SHA2/SHA384/SHA512";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            if (signatures.Any(s =>
                s.DigestAlgorithm.Value == KnownOids.SHA256 ||
                s.DigestAlgorithm.Value == KnownOids.SHA384 ||
                s.DigestAlgorithm.Value == KnownOids.SHA512))
            {
                return TestResult.Pass;
            }
            return TestResult.Fail;
        }
    }
}
