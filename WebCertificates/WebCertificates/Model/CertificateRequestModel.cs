namespace WebCertificates.Model
{
    class CertificateRequestModel
    {
        public string SubjectDomain { get; set; }
        public string CaTemplate { get; set; }
        public string CertRequest { get; set; }
        public string Privatekey { get; set; }
        public string CertWithChain { get; set; }
    }
}
