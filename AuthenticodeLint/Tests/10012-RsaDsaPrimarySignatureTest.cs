using System.Collections.Generic;
using System.Linq;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class RsaDsaPrimarySignatureTest : IAuthenticodeSignatureTest
    {
        public int Test => 10012;

        public string TestName => "RSA/DSA Primary Signature";

        public string ShortDescription => "Primary signature should be RSA or DSA.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var primary = graph.FirstOrDefault();
            //There are zero signatures.
            if (primary == null)
            {
                return TestResult.Fail;
            }
            var info = BitStrengthCalculator.CalculateStrength(primary.Certificate);
            if (info.AlgorithmName != PublicKeyAlgorithm.RSA && info.AlgorithmName != PublicKeyAlgorithm.DSA)
            {
                verboseWriter.LogSignatureMessage(primary, $"Primary signature should use RSA or DSA key but uses {info.AlgorithmName.ToString()}");
                return TestResult.Fail;
            }
            return TestResult.Pass;
        }
    }
}
