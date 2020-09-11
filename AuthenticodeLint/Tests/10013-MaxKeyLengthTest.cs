using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class MaxKeyLengthTest : IAuthenticodeSignatureTest
    {
        private const int MAX_ECDSA_KEY_SIZE = 384;
        private const int MAX_RSA_KEY_SIZE = 4096;
        private const int MAX_DSA_KEY_SIZE = 1024;

        public int Test => 10013;

        public string TestName => "Maximum Key Length";

        public string ShortDescription => "Validates the maximum key length of a signing certificate.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.Any, deep: true);
            var result = TestResult.Pass;
            foreach (var signature in signatures)
            {
                var keyInfo = BitStrengthCalculator.CalculateStrength(signature.Certificate);
                switch (keyInfo.AlgorithmName)
                {
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature uses ECDSA with an unknown curve.");
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize > MAX_ECDSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses ECDSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_ECDSA_KEY_SIZE}.");
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.ECDSA:
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown RSA key size.");
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize > MAX_RSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses RSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_RSA_KEY_SIZE}.");
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA:
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize is null:
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown DSA key size.");
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize > MAX_DSA_KEY_SIZE:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses DSA signature with a key size of {keyInfo.BitSize} exeeding maximum size of {MAX_DSA_KEY_SIZE}.");
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.DSA:
                        break;
                    default:
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses an unknown algorithm.");
                        result = TestResult.Fail;
                        break;
                }
            }
            return result;
        }
    }
}
