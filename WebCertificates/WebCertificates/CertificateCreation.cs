using System;
using System.Collections.Generic;
using WebCertificates.Exceptions;
using WebCertificates.Model;
using CERTCLILib;
using CERTENROLLLib;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.IO;
using System.Linq;

namespace WebCertificates
{
    public class CertificateCreation
    {
        private const int MaximumLineLength = 64;

        // These values will be needed for our certificate enrollment process
        private const int CC_DEFAULTCONFIG = 0;
        private const int CC_UIPICKCONFIG = 0x1;
        private const int CR_IN_BASE64 = 0x1;
        private const int CR_IN_FORMATANY = 0;
        private const int CR_IN_PKCS10 = 0x100;
        private const int CR_DISP_ISSUED = 0x3;
        private const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private const int CR_OUT_BASE64 = 0x1;
        private const int CR_OUT_BASE64HEADER = 0;
        private const int CR_OUT_CHAIN = 0x100;

        // These values will be needed to retrieve and remove the private key when we are done
        private const UInt32 NCRYPT_MACHINE_KEY_FLAG = 0x00000020;
        private const UInt32 CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000;
        private const UInt32 CRYPT_DELETEKEYSET = 0x00000010;

        // We need to p/invoke these libraries in order to work with privatekeys
        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Int32 NCryptDeleteKey(
            [In] SafeNCryptKeyHandle hKey,
            [In] UInt32 dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Boolean CryptAcquireContext(
           out IntPtr phProv,
           String pszContainer,
           String pszProvider,
           uint dwProvType,
           uint dwFlags
            );

        [DllImport("Advapi32.dll", EntryPoint = "CryptReleaseContext", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptReleaseContext(
            IntPtr hProv,
            Int32 dwFlags   // Reserved. Must be 0.
            );

        [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Boolean CryptAcquireCertificatePrivateKey(
            [In] IntPtr pCert,
            [In] UInt32 dwFlags,
            [In, Optional] IntPtr pvReserved,
            [Out] out SafeNCryptKeyHandle phCryptProv,
            [Out] out UInt32 pdwKeySpec,
            [Out] out Boolean pfCallerFreeProv
            );

        private string CreateRequest(string subject, string catemplate, CertificateRequestModel model)
        {
            // Create all objectes we need.
            CX509CertificateRequestPkcs10 Pkcs10 = new CX509CertificateRequestPkcs10();
            CX509PrivateKey PrivateKey = new CX509PrivateKey();
            CCspInformation CSP = new CCspInformation();
            CCspInformations CSPs = new CCspInformations();
            CX500DistinguishedName DN = new CX500DistinguishedName();
            CX509Enrollment Enroll = new CX509Enrollment();
            CObjectIds ObjectIds = new CObjectIds();
            CObjectId ObjectId = new CObjectId();
            CX509ExtensionKeyUsage ExtensionKeyUsage = new CX509ExtensionKeyUsage();
            CX509ExtensionEnhancedKeyUsage X509ExtensionEnhancedKeyUsage = new CX509ExtensionEnhancedKeyUsage();
            string Request;

            // Create our Cryptographic Service Provider object and add it to the CSP collection
            CSP.InitializeFromName("Microsoft RSA SChannel Cryptographic Provider");
            CSPs.Add(CSP);

            // Create our private key object
            PrivateKey.ContainerName = subject;
            PrivateKey.Length = 2048;
            PrivateKey.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            PrivateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            PrivateKey.MachineContext = true;
            PrivateKey.CspInformations = CSPs;
            PrivateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            PrivateKey.ProviderType = X509ProviderType.XCN_PROV_RSA_SCHANNEL;

            PrivateKey.Create();

            // Convert the private key to PEM format and write our private key to our model so we can use it later
            // We have to extract our private key at this stage because afterwards .NET makes it too complicated
            // Also see: https://www.pkisolutions.com/accessing-and-using-certificate-private-keys-in-net-framework-net-core/
            string privatkeyBase64Blob = PrivateKey.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64);

            byte[] privatekeyExported = ExportPrivateKey(privatkeyBase64Blob);

            model.Privatekey = PemEncode(privatekeyExported);

            // Initialize the PKCS#10 certificate request object based on the private key
            // Set the context to machine so this cert will work with the computer certificate store
            // Pass a template to use. Because of this we do not specify extended key usage since the
            // template does this for us
            Pkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, PrivateKey, catemplate);

            // Create the Distinguished Name object with the subject name we took as input
            // and add it to our request
            DN.Encode("CN=" + subject.Trim(), X500NameFlags.XCN_CERT_NAME_STR_NONE);
            Pkcs10.Subject = DN;

            // Create our enrollment request and transform it to a string
            Enroll.InitializeFromRequest(Pkcs10);
            Request = Enroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return Request;
        }

        private string SendRequest(string Request, int CertIntervalAttempts = 10, int CertIntervalSleep = (6 * 1000))
        {
            //  Create all the objects that will be required
            CCertConfig CertConfig = new CCertConfig();
            CCertRequest CertRequest = new CCertRequest();
            string CAConfig;
            int iDisposition;
            string strDisposition;
            string strCert;


            // Retrieve the system default CA to use for our request
            CAConfig = CertConfig.GetConfig(CC_DEFAULTCONFIG);

            // Submit the cert request in base64 and allow the system to figure out if Pkcs#7 or Pkcs#10
            iDisposition = CertRequest.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, Request, null, CAConfig);

            int certWaitCount = 0;

            while (CR_DISP_ISSUED != iDisposition) // We are not enrolled
            {
                strDisposition = CertRequest.GetDispositionMessage();

                if (CR_DISP_UNDER_SUBMISSION == iDisposition) // Our request is pending
                {
                    if (certWaitCount > CertIntervalAttempts)
                    {
                        throw new CertificateRequestTimeoutException($"The submission timed out: {strDisposition} Last status: {CertRequest.GetLastStatus().ToString()}");
                    }
                    ++certWaitCount;
                    Thread.Sleep(CertIntervalSleep);
                    continue;
                }

                else // Our request has failed
                {
                    throw new CertificateRequestFailedException($"The submission failed: {strDisposition} Last status: {CertRequest.GetLastStatus().ToString()}");
                }

            }

            // Retrieve our cert in base64 with the entire cert chain included
            // We need the entire chain for this cert to work on Linux systems
            string Base64CertWithChain = CertRequest.GetCertificate(CR_OUT_BASE64HEADER | CR_OUT_CHAIN);

            // The string which represents the certificate including the chain is still not useable for Linux systems
            // Windows will not append each base64 block which represts a certificate with the correct decorations
            // We must extract each certificate in the chain from the string

            // Strip the string we have down to just the base64 code
            string Base64CertWithChainParsed = Base64CertWithChain.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "").Replace("\r", "").Replace("\n", "");

            // Decode the base64 content and add it to a SignedCms which represents a collection of certificates
            byte[] CertDecodedContent = Convert.FromBase64String(Base64CertWithChainParsed);

            SignedCms CertContainer = new SignedCms();
            CertContainer.Decode(CertDecodedContent);

            StringBuilder CertificateTempString = new StringBuilder();

            // Iterate over ever certificate in our SignedCms and export every one as base64 with correct decorations
            foreach (var cert in CertContainer.Certificates)
            {
                CertificateTempString.Append(ConvertCertificateToBase64(cert));
            }

            strCert = CertificateTempString.ToString();

            return strCert;
        }

        private string ConvertCertificateToBase64(X509Certificate2 cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        // Adapted from https://stackoverflow.com/a/40306616
        private byte[] ExportPrivateKey(String cspBase64Blob)
        {
            if (String.IsNullOrEmpty(cspBase64Blob) == true)
                throw new ArgumentNullException(nameof(cspBase64Blob));

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();

            csp.ImportCspBlob(Convert.FromBase64String(cspBase64Blob));

            if (csp.PublicOnly)
                throw new ArgumentException("CSP does not contain a private key!", nameof(csp));

            RSAParameters parameters = csp.ExportParameters(true);

            List<byte[]> list = new List<byte[]>
      {
         new byte[] {0x00},
         parameters.Modulus,
         parameters.Exponent,
         parameters.D,
         parameters.P,
         parameters.Q,
         parameters.DP,
         parameters.DQ,
         parameters.InverseQ
      };

            return SerializeList(list);
        }

        // Adapted from https://stackoverflow.com/a/40306616
        private byte[] Encode(byte[] inBytes, bool useTypeOctet = true)
        {
            int length = inBytes.Length;
            List<byte> bytes = new List<byte>();

            if (useTypeOctet == true)
                bytes.Add(0x02); // INTEGER

            bytes.Add(0x84); // Long format, 4 bytes
            bytes.AddRange(BitConverter.GetBytes(length).Reverse());
            bytes.AddRange(inBytes);

            return bytes.ToArray();
        }

        // Adapted from https://stackoverflow.com/a/40306616
        private String PemEncode(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            string base64 = Convert.ToBase64String(bytes);

            StringBuilder b = new StringBuilder();
            b.AppendLine("-----BEGIN RSA PRIVATE KEY-----");

            for (int i = 0; i < base64.Length; i += MaximumLineLength)
                b.AppendLine($"{ base64.Substring(i, Math.Min(MaximumLineLength, base64.Length - i)) }");

            b.AppendLine("-----END RSA PRIVATE KEY-----");

            return b.ToString();
        }

        // Adapted from https://stackoverflow.com/a/40306616
        private byte[] SerializeList(List<byte[]> list)
        {
            if (list == null)
                throw new ArgumentNullException(nameof(list));

            byte[] keyBytes = list.Select(e => Encode(e)).SelectMany(e => e).ToArray();

            BinaryWriter binaryWriter = new BinaryWriter(new MemoryStream());
            binaryWriter.Write((byte)0x30); // SEQUENCE
            binaryWriter.Write(Encode(keyBytes, false));
            binaryWriter.Flush();

            byte[] result = ((MemoryStream)binaryWriter.BaseStream).ToArray();

            binaryWriter.BaseStream.Dispose();
            binaryWriter.Dispose();

            return result;
        }

        private X509Certificate2 FindCertificateInMachineStore(string SubjectDomain)
        {
            X509Certificate2 CertToFind = new X509Certificate2();
            X509Store Store = new X509Store("REQUEST", StoreLocation.LocalMachine);
            Store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection CertsFound = Store.Certificates.Find(X509FindType.FindBySubjectName, SubjectDomain, false);

            if (CertsFound.Count == 0 || CertsFound.Count >= 2)
            {
                CertToFind = null;
                return CertToFind;
            }

            Store.Close();

            return CertToFind = CertsFound[0];
        }

        public bool DeleteRequestFromStore(X509Certificate2 certificate)
        {
            X509Store Store = new X509Store("REQUEST", StoreLocation.LocalMachine);

            try
            {
                Store.Open(OpenFlags.ReadWrite);
                Store.Remove(certificate);
            }
            catch (Exception ex)
            {
                return false;
            }
            finally
            {
                Store.Close();
            }

            return true;
        }

        private bool DeleteCSPPrivatekey(AsymmetricAlgorithm Privatekey)
        {
            if (Privatekey == null)
            {
                return false;
            }

            string KeyContainer;
            string CSPName; // Cryptographic Service Provider name 
            UInt32 CSPType; // Cryptographic Serivce Provider type

            // Retrieve properties of our privatekey based on CSP (RSA or DSA)
            // This is needed for the removal step
            switch (Privatekey)
            {
                case RSACryptoServiceProvider _:
                    KeyContainer = ((RSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.KeyContainerName;
                    CSPName = ((RSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderName;
                    CSPType = (UInt32)((RSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderType;
                    break;
                case DSACryptoServiceProvider _:
                    KeyContainer = ((DSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.KeyContainerName;
                    CSPName = ((DSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderName;
                    CSPType = (UInt32)((DSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderType;
                    break;
                default:
                    Privatekey.Dispose();
                    return false;
            }

            IntPtr phProv = IntPtr.Zero;

            // Delete the privatekey from the local machine store
            bool KeyRemovalStatus = CryptAcquireContext(out phProv, KeyContainer, CSPName, CSPType, CRYPT_DELETEKEYSET | NCRYPT_MACHINE_KEY_FLAG);

            if (!KeyRemovalStatus)
            {
                // If we did not find a key te delete from the machine store, try the current user store to ensure clean-up
                KeyRemovalStatus = CryptAcquireContext(out phProv, KeyContainer, CSPName, CSPType, CRYPT_DELETEKEYSET);
            }

            if (phProv.ToInt32() != 0)
            {
                // If a privatekey was removed we have an open handle that we must close
                CryptReleaseContext(phProv, 0);
            }

            Privatekey.Dispose();

            return KeyRemovalStatus;
            //return false;
        }

        bool DeleteCNGPrivatekey(SafeNCryptKeyHandle phPrivatekey)
        {
            Int32 hresult = NCryptDeleteKey(phPrivatekey, 0);
            phPrivatekey.Dispose();
            return hresult == 0;
        }

        bool DeletePrivateKey(X509Certificate2 cert)
        {
            if (!CryptAcquireCertificatePrivateKey(cert.Handle, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, IntPtr.Zero, out SafeNCryptKeyHandle phCryptProvOrNCryptKey, out UInt32 pdwKeySpec, out Boolean _))
            {
                return false;
            }

            if (pdwKeySpec == UInt32.MaxValue)
            {
                return DeleteCNGPrivatekey(phCryptProvOrNCryptKey);
            }
            else
            {
                return DeleteCSPPrivatekey(cert.PrivateKey);
            }
        }

        public Dictionary<string, string> GetCertificate(string SubjectDomain, string CATemplate, int CertIntervalAttempts = 10, int CertIntervalSleep = (6 * 1000))
        {
            CertificateRequestModel CertRequest = new CertificateRequestModel();
            CertRequest.SubjectDomain = SubjectDomain;
            CertRequest.CaTemplate = CATemplate;

            string request;
            string certificate;

            try
            {
                request = CreateRequest(SubjectDomain, CATemplate, CertRequest);
                certificate = SendRequest(request, CertIntervalAttempts, CertIntervalSleep);
            }
            catch (Exception ex)
            {
                throw;
            }
            finally
            {
                X509Certificate2 CertToRemove = FindCertificateInMachineStore(SubjectDomain);

                if (CertToRemove != null)
                {
                    bool RemovePrivatekeyOutcome = DeletePrivateKey(CertToRemove);
                    bool RemovalOutcome = DeleteRequestFromStore(CertToRemove);
                }
                else
                {
                    throw new CertificateNotFoundException($"No certificates found or failed to remove certificates for {SubjectDomain}");
                }

            }

            CertRequest.CertRequest = request;
            CertRequest.CertWithChain = certificate;

            Dictionary<string, string> dict = new Dictionary<string, string>
            {
                { "Domain", CertRequest.SubjectDomain },
                { "CertRequest", CertRequest.CertRequest },
                { "CertWithChain", CertRequest.CertWithChain },
                { "CertPrivatekey", CertRequest.Privatekey }
            };

            return dict;
        }

    }
}
