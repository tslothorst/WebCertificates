# Requesting and distributing ssl certificates for non-Windows clients from Windows CA

I wrote this library to simplify the task of requesting certficates from a Windows based Certificate Authority in the local domain. For Windows clients it's easy enough to enroll themselves with a Windows based CA through Active Directory. Non-Windows clients have a much harder time doing this since all steps to enroll them will have to be done manually and the certificate has to be converted into a format which can be widely used. 


## How does it work?
While .NET 4.7.2 and .NET Core 3 added some extra features to request certificates (the [CertificateRequest class](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest?view=net-5.0)) it still does not support the whole process. You can create a useable request, but there is no compatible way to submit this to your friendly neighbourhood Windows CA and to handle any of the steps which ideally come after this. So sadly there is no real "modern" kind of way to solve this problem. The only complete ways offered are through COM objects (so no .NET Core or .NET 5) and p/Invoke to use some methods which aren't available as COM object.

## Implementation
In order to be able to walk through the whole process we have to resort to using the Win32 api to create our request and submit it to the CA ([CERTENROLL](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/certenroll-interfaces) and [CERTCLI](https://docs.microsoft.com/en-us/windows/win32/api/certcli/)). When we have our certificate (or our request failed somehow) we must clean up the mess we made. This means removing the pending request from the Windows Certificate Store and removing the private key associated with it. Finding and removing the certificate from the [Windows Certificate Store](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store?view=netframework-4.8) can be done through .NET classes. Removing the privatekey associated with the certificate has to be done through the Win32 api, since .NET Framework does not offer any direct route to do this. There are no COM objects either for this like CERTENROLL and CERTCLI so this has to be done with p/Invoke: ncrypt.dll, advapi32.dll and Crypt32.dll. 

For reference the header files: 
- [ncrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/) 
- [wincrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/) 

## How do I use it?
When you add this library as a reference to your own project, it offers a single function to call:
```cs
public Dictionary<string, string> GetCertificate(string SubjectDomain, string CATemplate, int CertIntervalAttempts = 10, int CertIntervalSleep = (6 * 1000))
```
`SubjectDomain` is the domain you want a certificate for. `CATemplate` is the CA template to use, an overview of the default offered as available from Microsoft but your administrator might have renamed them or made custom ones. `CertIntervalAttempts` and `CertIntervalSleep` will determine how many times you are willing to check if you have been enrolled and at what interval to keep polling. Use these values if needed to poll and wait for how long you want. Useful for dealing with slow resources on the network. 

If all goes as planned the output is a dictionary containing the following:
`Domain`: The domain you specified.
`CertRequest`: The request which was generated and submitted to the CA.
`CertWithChain`: The certificate in base64 with chain and headers.
`CertPrivatekey`: The private key for the certificate in base64 and with headers.

## Exceptions
This library can throw a few custom exceptions of it's own if something goes wrong:

```cs
CertificateRequestFailedException()
```
The certificate request has failed. The exception includes why the request failed as the message.

```cs
CertificateRequestTimeoutException()
```
The maximum time specified to wait for the certificate request to complete has expired before any reply from the CA was received. Either the CA was unreachable or no auto enrollment is enabled, either of which would otherwise mean we be waiting forever.

```cs
CertificateNotFoundException()
```
In the clean-up phase which runs after succesful completion or failure the pending request could not be found in the Windows Certificate Store. This is important because as long as something lingers (either the request or the privatekey associated with it) any new tries will fail. Most likely you'll have to do some manual clean-up before retrying.

## System Requirements
This library as is will work on any Windows based host with .NET Framework 4.8.