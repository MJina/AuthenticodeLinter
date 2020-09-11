using System;
using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class PublisherInformationUrlHttpsTest : IAuthenticodeSignatureTest
    {
        public int Test => 10005;

        public string TestName => "Publisher Information URL HTTPS";

        public string ShortDescription => "Checks that the signature uses HTTPS for the publisher's URL.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
            var result = TestResult.Pass;
            foreach(var signature in signatures)
            {
                PublisherInformation info = null;
                foreach(var attribute in signature.SignedAttributes)
                {
                    if (attribute.Oid.Value == KnownOids.OpusInfo)
                    {
                        info = new PublisherInformation(attribute.Values[0]);
                        break;
                    }
                }
                if (info == null || info.IsEmpty)
                {
                    result = TestResult.Fail;
                    verboseWriter.LogSignatureMessage(signature, "Signature does not have any publisher information.");
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(info.UrlLink))
                    {
                        result = TestResult.Fail;
                        verboseWriter.LogSignatureMessage(signature, "Signature does not have an accompanying URL.");
                    }
                    else if (!info.UrlLink.StartsWith(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                    {
                        result = TestResult.Fail;
                        verboseWriter.LogSignatureMessage(signature, $"Signature's publisher information URL \"{info.UrlLink}\" does not use the secure HTTPS scheme.");
                    }
                }
            }
            return result;
        }
    }
}
