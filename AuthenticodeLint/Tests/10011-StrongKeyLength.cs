using System;
using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class StrongKeyLengthTest : IAuthenticodeSignatureTest
    {
        private const int MIN_RSADSA_KEY_SIZE = 2048;
        private const int MIN_ECDSA_KEY_SIZE = 256;

        public int Test => 10011;

        public string TestName => "Strong Key Length";

        public string ShortDescription => "Validates the key length of a signing certificate.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.Any | SignatureKind.Any);
            var result = TestResult.Pass;
            int signatureIndex = 0;
            foreach (var signature in signatures)
            {
                string thumbprint = signature.Certificate.Thumbprint;
                string errMsg = "";
                int keySize = 0;
                var keyInfo = BitStrengthCalculator.CalculateStrength(signature.Certificate);
                if (!(keyInfo.BitSize is null))
                    keySize = (int)keyInfo.BitSize;
                string signatureAlgorithm = "";
                switch (keyInfo.AlgorithmName)
                {
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize is null:
                        errMsg = "Signature uses ECDSA with an unknown curve.";
                        verboseWriter.LogSignatureMessage(signature, "Signature uses ECDSA with an unknown curve.");
                        signatureAlgorithm = "ECDSA";
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.ECDSA when keyInfo.BitSize < MIN_ECDSA_KEY_SIZE:
                        errMsg = $"Signature uses a ECDSA key of size {keyInfo.BitSize} which is below the recommended {MIN_ECDSA_KEY_SIZE}.";
                       verboseWriter.LogSignatureMessage(signature, $"Signature uses a ECDSA key of size {keyInfo.BitSize} which is below the recommended {MIN_ECDSA_KEY_SIZE}.");
                        result = TestResult.Fail;
                        signatureAlgorithm = "ECDSA";
                        break;
                    case PublicKeyAlgorithm.ECDSA:
                        signatureAlgorithm = "ECDSA";
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize is null:
                        errMsg = "Signature has an unknown RSA key size.";
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown RSA key size.");
                        result = TestResult.Fail;
                        signatureAlgorithm = "RSA";
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize < MIN_RSADSA_KEY_SIZE:
                        errMsg = $"Signature uses a RSA key of size {keyInfo.BitSize} which is below the recommended {MIN_RSADSA_KEY_SIZE}.";
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses a RSA key of size {keyInfo.BitSize} which is below the recommended {MIN_RSADSA_KEY_SIZE}.");
                        signatureAlgorithm = "RSA";
                        result = TestResult.Fail;
                        break;
                    case PublicKeyAlgorithm.RSA when keyInfo.BitSize >= MIN_RSADSA_KEY_SIZE:
                        signatureAlgorithm = "RSA";
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize is null:
                        errMsg = "Signature has an unknown DSA key size.";
                        verboseWriter.LogSignatureMessage(signature, "Signature has an unknown DSA key size.");
                        result = TestResult.Fail;
                        signatureAlgorithm = "DSA";
                        break;
                    case PublicKeyAlgorithm.DSA when keyInfo.BitSize < MIN_RSADSA_KEY_SIZE:
                        //Effectively, 1024 is the max for a DSA key, so this will likely always fail.
                        errMsg = $"Signature uses a DSA key of size {keyInfo.BitSize} which is below the recommended {MIN_RSADSA_KEY_SIZE}.";
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses a DSA key of size {keyInfo.BitSize} which is below the recommended {MIN_RSADSA_KEY_SIZE}.");
                        result = TestResult.Fail;
                        signatureAlgorithm = "DSA";
                        break;
                    case PublicKeyAlgorithm.DSA:
                        signatureAlgorithm = "DSA";
                        break;
                    default:
                        errMsg = $"Signature uses an unknown algorithm.";
                        verboseWriter.LogSignatureMessage(signature, $"Signature uses an unknown algorithm.");
                        result = TestResult.Fail;
                        break;
                }
                DBConnect.InsertPublicKeyInfo(Program.appName, Program.fileName, signatureAlgorithm, keySize, thumbprint, errMsg, signatureIndex);
                signatureIndex++;
            }
            return result;
        }
    }
}
