using AuthenticodeLinter.Tests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace AuthenticodeLinter
{
    public class XmlTestResultCollector : ITestResultCollector
    {
        private string _path;
        private readonly XDocument _document;
        private XElement _currentSet;

        public XmlTestResultCollector(string path)
        {
            _path = path;
            _document = new XDocument();
            _document.Add(new XElement("results"));
        }

        public void BeginSet(string setName)
        {
            _currentSet = new XElement("file", new XAttribute("path", setName));
        }

        public void CollectResult(IAuthenticodeTest test, TestResult result, IReadOnlyList<string> additionalOutput, Boolean dontInsertRulesTable, string appID, string fileName, string thumbprint, string signatureHash, string portal)
        {
            var additionalOutputElements = additionalOutput.Select(msg => new XElement("message", msg));
            _currentSet.Add(new XElement("check",
                new XAttribute("testId", test.Test),
                new XAttribute("result", result),
                new XElement("messages", additionalOutputElements.ToArray())));
        }

        public void CompleteSet()
        {
            _document.Root.Add(_currentSet);
            _currentSet = null;
        }

        public void Flush() => _document.Save(_path);
    }
}
