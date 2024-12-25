from contextlib import closing
from OpenSSL import crypto
from cert_chain_resolver.models import CertificateChain, Cert

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request  # type: ignore

try:
    unicode  # type: ignore
except NameError:
    unicode = str

try:
    from typing import Any, Optional
    from cert_chain_resolver.castore.base_store import CAStore
except ImportError:
    pass


def _download(url):
    # type: (str) -> Any
    req = Request(url, headers={"User-Agent": "Cert/fixer"})

    with closing(urlopen(req)) as resp:
        return resp.read()


def resolve(bytes_cert, _chain=None, root_ca_store=None, cert_bytes=None):
    # type: (bytes, Optional[CertificateChain], Optional[CAStore]) -> CertificateChain
    """A recursive function that follows the CA issuer chain

    Args:
        bytes_cert: A DER/PKCS7/PEM certificate
        _chain: Chain to complete. Defaults to None.
        root_ca_store: A CAStore to use for completing the chain with a root certificate in case
            the intermediates do not provide a location

    Returns:
        All resolved certificates in chain
    """

    cert = Cert.load(bytes_cert)
    if not _chain:
        _chain = CertificateChain()
    if not cert_bytes:
        cert_bytes = []
    if cert in _chain:
        # Prevent recursion in case the cert is self-referential
        return _chain
    _chain += cert
    cert_bytes.append(bytes_cert)
    parent_cert = None
    if cert.ca_issuer_access_location:
        parent_cert = _download(cert.ca_issuer_access_location)
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, parent_cert)  # 加载父证书
        parent_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)  # 转换为PEM格式
    if parent_cert:
        return resolve(parent_cert, _chain=_chain, root_ca_store=root_ca_store, cert_bytes=cert_bytes)
    elif not _chain.root and root_ca_store:
        _bytes_cert = bytes(root_ca_store.find_issuer(cert)[0])
        cert_bytes.append(_bytes_cert)

    return cert_bytes
