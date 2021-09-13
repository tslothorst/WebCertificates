using System;

namespace WebCertificates.Exceptions
{
    public class CertificateRequestTimeoutException : Exception
    {
        public CertificateRequestTimeoutException()
        {
        }

        public CertificateRequestTimeoutException(string message) : base(message)
        {
        }

        public CertificateRequestTimeoutException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}
