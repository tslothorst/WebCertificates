using System;

namespace WebCertificates.Exceptions
{
    [Serializable]
    public class CertificateRequestFailedException : Exception
    {
        public CertificateRequestFailedException()
        {
        }

        public CertificateRequestFailedException(string message) : base(message)
        {
        }

        public CertificateRequestFailedException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}
