using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public abstract class CertificateChainTest : IAuthenticodeSignatureTest
    {
        public abstract int Test { get; }
        public abstract string TestName { get; }
        public abstract string ShortDescription { get; }
        public abstract TestSet TestSet { get; }

        protected abstract bool ValidateChain(ICmsSignature signer, X509Chain chain, SignatureLogger verboseWriter);

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
            var result = TestResult.Pass;
            foreach (var signature in signatures)
            {
                var certificates = signature.AdditionalCertificates;
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.ExtraStore.AddRange(certificates);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    //The purpose of this check is not to validate the chain, completely.
                    //The chain is needed so we know which certificate is the root and intermediates so we know which to validate and which not to validate.
                    //It is possible to have a valid Authenticode signature if the certificate is expired but was
                    //timestamped while it was valid. In this case we still want to successfully build a chain to perform validation.
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                    bool success = chain.Build(signature.Certificate);
                    if (!success)
                    {
                        verboseWriter.LogSignatureMessage(signature, $"Cannot build a chain successfully with signing certificate {signature.Certificate.SerialNumber}.");
                        result = TestResult.Fail;
                        continue;
                    }
                    if (!ValidateChain(signature, chain, verboseWriter))
                    {
                        result = TestResult.Fail;
                    }
                }
            }
            return result;
        }
    }
}
