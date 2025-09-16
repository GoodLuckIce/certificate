from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime

# 加载根证书和私钥
with open("root_ca.pem", "rb") as f:
    root_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
with open("root_ca.key", "rb") as f:
    root_ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# 生成子证书私钥
sub_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

dnsName = "smartearth.cn"

# 设置子证书信息
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"*." + dnsName),
])

# 创建子证书，绑定通配符域名 *.example.com（可添加更多域名）
sub_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(root_ca_cert.subject)
    .public_key(sub_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"*." + dnsName),  # 通配符域名
            x509.DNSName(dnsName)     # 可选：包含根域名
        ]),
        critical=False,
    )
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    .sign(root_ca_key, hashes.SHA256(), default_backend())
)

# 保存子证书私钥到 cert.key 文件
with open(dnsName + ".key", "wb") as f:
    f.write(
        sub_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# 保存子证书到 cert.pem 文件
with open(dnsName + ".pem", "wb") as f:
    f.write(sub_cert.public_bytes(serialization.Encoding.PEM))