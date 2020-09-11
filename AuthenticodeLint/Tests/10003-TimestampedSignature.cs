using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;


namespace AuthenticodeLinter.Tests
{
    public class TimestampedTest : IAuthenticodeSignatureTest
    {
        public int Test => 10003;

        public string TestName => "Timestamped Signature";

        public string ShortDescription => "Check if signatures have a timestamp counter signer.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var pass = true;
            int signatureIndex = 0;
            foreach (var signature in signatures)
            {
                var counterSignatures = signature.VisitAll(SignatureKind.AnyCounterSignature).ToList();
                int ts = counterSignatures.Count;
                var isSigned = false;
                var strongSign = 0;
                var tsDigestString = "";
                string serialNumber = "";
                string thumbprint = signature.Certificate.Thumbprint;
                var digestStr = HashHelpers.GetHashForSignature(signature);//message digest of siganture(signature->details->advance->msg digest)
                DBConnect.InsertSignatureTable(Program.fileName, Program.appName, digestStr, signature.DigestAlgorithm.FriendlyName, signature.Certificate.Version, ts, thumbprint, signature.Certificate.Issuer, signature.Certificate.IssuerName.Name, signature.Certificate.Subject, signature.Certificate.SubjectName.Name, signatureIndex);
                System.DateTime notBeforeDate = signature.Certificate.NotBefore;
                System.DateTime notAfterDate = signature.Certificate.NotAfter;
                serialNumber = signature.Certificate.SerialNumber;
                DBConnect.InsertSignatureDateTable(Program.appName, Program.fileName, digestStr, notBeforeDate.Year, notBeforeDate.Month, notBeforeDate.Day, notAfterDate.Year, notAfterDate.Month, notAfterDate.Day, thumbprint, signatureIndex);
                X509ExtensionCollection extensions = signature.Certificate.Extensions;
                
                int tssignatureIndex = 0;
                foreach (var counterSignature in counterSignatures)
                {
                    tsDigestString = HashHelpers.GetHashForSignature(counterSignature);//message digest of siganture(signature->details->advance->msg digest)
                    System.DateTime tsNotBeforeDate = counterSignature.Certificate.NotBefore;
                    System.DateTime tsNotAfterDate = counterSignature.Certificate.NotAfter;

                    DBConnect.InsertTSSignatureDateTable(Program.appName, Program.fileName, tsDigestString, tsNotBeforeDate.Year, tsNotBeforeDate.Month, tsNotBeforeDate.Day, tsNotAfterDate.Year, tsNotAfterDate.Month, tsNotAfterDate.Day, counterSignature.Certificate.Thumbprint, tssignatureIndex);
                    isSigned = true;
                    if (counterSignature.DigestAlgorithm.Value == signature.DigestAlgorithm.Value)
                    {
                        strongSign++;
                        DBConnect.InsertTSSignatureTable(Program.appName, Program.fileName, tsDigestString, counterSignature.DigestAlgorithm.FriendlyName, counterSignature.Certificate.Version, 1, thumbprint, counterSignature.Certificate.Thumbprint, counterSignature.Certificate.Issuer, counterSignature.Certificate.IssuerName.Name, counterSignature.Certificate.Subject, counterSignature.Certificate.SubjectName.Name);

                    }
                    else
                        DBConnect.InsertTSSignatureTable(Program.appName, Program.fileName, tsDigestString, counterSignature.DigestAlgorithm.FriendlyName, counterSignature.Certificate.Version, 0, thumbprint, counterSignature.Certificate.Thumbprint, counterSignature.Certificate.Issuer, counterSignature.Certificate.IssuerName.Name, counterSignature.Certificate.Subject, counterSignature.Certificate.SubjectName.Name);
                }
                if (!isSigned && strongSign >= 1)
                {
                    throw new InvalidOperationException("Unexpectedly have a strong signature.");
                }
                if (!isSigned)
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature is not timestamped.");
                    pass = false;
                }
                else if (strongSign == 0)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Signature is not timestamped with the expected hash algorithm {signature.DigestAlgorithm.FriendlyName}.");
                    pass = false;
                }
                signatureIndex++;
            }

            return pass ? TestResult.Pass : TestResult.Fail;
        }
    }
}
