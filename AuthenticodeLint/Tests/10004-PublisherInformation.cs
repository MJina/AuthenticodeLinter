using System;
using System.Collections.Generic;
using AuthenticodeExaminer;

namespace AuthenticodeLinter.Tests
{
    public class PublisherInformationPresentTest : IAuthenticodeSignatureTest
    {
        public int Test => 10004;

        public string Msg = "";
        public string link = "";
        public string description = "";

        public string TestName => "Publisher Information";

        public string ShortDescription => "Checks that the signature provided publisher information.";

        public TestSet TestSet => TestSet.All;
        
        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature, deep: true);
            var result = TestResult.Pass;
            foreach (var signature in signatures)
            {
                link = ""; 
                Msg = "";
                description = "";
                link = "";
                PublisherInformation info = null;
                foreach (var attribute in signature.SignedAttributes)
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
                    Msg = "Signature does not have any publisher information.";
                    verboseWriter.LogSignatureMessage(signature, "Signature does not have any publisher information.");
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(info.Description))
                    {
                        result = TestResult.Fail;
                        Msg = "Signature does not have an accompanying description.";
                        verboseWriter.LogSignatureMessage(signature, "Signature does not have an accompanying description.");
                    }

                    if (string.IsNullOrWhiteSpace(info.UrlLink))
                    {
                        result = TestResult.Fail;
                        Msg = "Signature does not have an accompanying URL.";
                        verboseWriter.LogSignatureMessage(signature, "Signature does not have an accompanying URL.");
                    }
                    else
                    {

                        if (!Uri.TryCreate(info.UrlLink, UriKind.Absolute, out _))
                        {
                            result = TestResult.Fail;
                            Msg = "Signature's accompanying URL is not a valid URI.";
                            verboseWriter.LogSignatureMessage(signature, "Signature's accompanying URL is not a valid URI.");
                        }
                    }
                }
                if (!string.IsNullOrWhiteSpace(info.UrlLink))
                    link = info.UrlLink;
                if (!string.IsNullOrWhiteSpace(info.Description))
                    description = info.Description;
                DBConnect.InsertPublisherTable(Program.appName, Program.fileName, link, signature.Certificate.Thumbprint, description, Msg);
            }
            return result;
        }
    }
}
