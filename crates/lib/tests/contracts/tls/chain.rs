use crate::behaviour::Check;
use tls::x509::trust::{Chain, Defect, Roots, blocks};
use tls::x509::{Certificate, Time};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("chain-validation", linked as Check)]
}

const ROOT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBLjCB1qADAgECAgEBMAoGCCqGSM49BAMCMA8xDTALBgNVBAMMBHJvb3QwHhcN
MjYwMTAxMDAwMDAwWhcNMzUxMjMwMDAwMDAwWjAPMQ0wCwYDVQQDDARyb290MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE04KCoXisgDSTojv0iEKQuotwTRddhuGN
rEV17W75wOskc+z53ouzxLDGjtAkPib/QAj7Sbei0slmTBj11y4qb6MjMCEwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDRwAwRAIg
HHCijogkZfsgW9d+3SuEDSoprGlYRWjL5iAQ6b93jUYCIFugMNNSvdfrFzsG+8of
F9tMsv5nns1t/SYcGlDVznfO
-----END CERTIFICATE-----
";

const INTER: &str = "\
-----BEGIN CERTIFICATE-----
MIIBMTCB16ADAgECAgECMAoGCCqGSM49BAMCMA8xDTALBgNVBAMMBHJvb3QwHhcN
MjYwMTAxMDAwMDAwWhcNMzUxMjMwMDAwMDAwWjAQMQ4wDAYDVQQDDAVpbnRlcjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABOc+iGhRMBdApduQixTxXzvPpcwHNiqH
j6ij/c7pWI3FCMOw21wO+ALIax9F62VZ+E+5KseuoH0IA9M6YARko32jIzAhMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMAoGCCqGSM49BAMCA0kAMEYC
IQCPglSpU25OSy03tA/jgnt2U4rUu0pNN/lWcKoU26VYQgIhAJFgZNe3n776PDM+
Lk7GuN9h61sbcsk6vAGRoppzEBqi
-----END CERTIFICATE-----
";

const LEAF: &str = "\
-----BEGIN CERTIFICATE-----
MIIBMjCB2aADAgECAgEDMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBWludGVyMB4X
DTI2MDEwMTAwMDAwMFoXDTM1MTIzMDAwMDAwMFowDzENMAsGA1UEAwwEbGVhZjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABO7BPn74wbZ7GzSdaXp0oIUTzqmQmFkL
00lWfsiT2V1HdHyCqCgVKXqJMZTMw3pkuxV/UGW6va8pf3QqrlR2lv2jJTAjMAwG
A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAw
RQIgG6nrZFJHdynnLqmqkYPnY3PlzH9DxBQonr2ZMxznJyoCIQDNMYQl3aMNUMTS
HSWTcZrBvhX/z2aOCkiUfnJ7BaU5XQ==
-----END CERTIFICATE-----
";

const FORGED: &str = "\
-----BEGIN CERTIFICATE-----
MIIBMjCB2aADAgECAgEDMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBWludGVyMB4X
DTI2MDEwMTAwMDAwMFoXDTM1MTIzMDAwMDAwMFowDzENMAsGA1UEAwwEbGVhZjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABO7BPn74wbZ7GzSdaXp0oIUTzqmQmFkL
00lWfsiT2V1HdHyCqCgVKXqJMZTMw3pkuxV/UGW6va8pf3QqrlR2lv2jJTAjMAwG
A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAw
RQIgG6nrZFJHdynnLqmqkYPnY3PlzH9DxBQonr2ZMxznJyoCIQDNMYQl3aMNUMTS
HSWTcZrBvhX/z2aOCkiUfnJ7BaU5XA==
-----END CERTIFICATE-----
";

fn cert(text: &str) -> Certificate {
    let block = &blocks(text).unwrap()[0];
    Certificate::parse(&block.data).unwrap()
}

fn held() -> Roots {
    let mut roots = Roots::default();
    roots.add(&blocks(ROOT).unwrap()[0].data).unwrap();
    roots
}

fn now() -> Time {
    Time {
        year: 2027,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    }
}

fn linked() {
    let inter = cert(INTER);
    let built = Chain::build(&cert(LEAF), std::slice::from_ref(&inter), &held(), now());
    assert_eq!(built.unwrap().certs().len(), 3);
    let fake = Chain::build(&cert(FORGED), &[inter], &held(), now());
    assert_eq!(fake.unwrap_err(), Defect::Forged);
    let rsa = cert(rsa::LEAF);
    let mut store = Roots::default();
    store.add(&blocks(rsa::ROOT).unwrap()[0].data).unwrap();
    assert_eq!(
        Chain::build(&rsa, &[], &store, now())
            .unwrap()
            .certs()
            .len(),
        2
    );
    let mut bad = rsa.clone();
    bad.signature[0] ^= 1;
    assert_eq!(
        Chain::build(&bad, &[], &store, now()).unwrap_err(),
        Defect::Forged
    );
    let mut wide = Roots::default();
    wide.add(&blocks(rsa::WIDE).unwrap()[0].data).unwrap();
    for sample in [rsa::SHA384, rsa::SHA512] {
        assert_eq!(
            Chain::build(&cert(sample), &[], &wide, now())
                .unwrap()
                .certs()
                .len(),
            2
        );
    }
}

mod rsa {
    pub(super) const ROOT: &str = "-----BEGIN CERTIFICATE-----
MIICxDCCAaygAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhyc2Et
cm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNTEyMzAwMDAwMDBaMBMxETAPBgNVBAMM
CHJzYS1yb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAruhdxxDU
5RiIcJV2H8wx013fcT732Alk6gYrYqZe8lhszot8sQQ4QJGJ+yJHjJ0TJRWEK3Fp
UzOYFQqIwOdoEeJC0PxDJ/rEbM1WwrXqcrA65Dlri/c8+o4pUCL1O6FCvmGneMIA
2AuNh/aFli1fzpdyVjRblESdH0cmpwMDz/EoqzYAL+EjB7+jotHtq4lBPs/+ZaaH
7v4KYtPSEtY+xiKftWQc914hSrEVIllsuTWttaPn9A3Gqjq0tsvLm44Q8bGHdY4D
GreeAFsSSGD0R7zoX3nlWf7Oa63t4+SBhm5EKl5u3REoyyIOpTiBH6SOesG8ZegD
YPA6jhcs7D1SlwIDAQABoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwICBDANBgkqhkiG9w0BAQsFAAOCAQEAKghCmkY/jrM27CoDm31Vjq04Q1tmdL2f
ZyIhg2GlcjyFd/kBFnj5tmhvL1CEehvbEjOxG0TPHdcK0QG3HnL69dabAdY0EStZ
O0D6lxVj5wAs2EWsk07DFcdgZl7qDhfgELQz0lID5CSVHG8rWZ3DfcL1Fno/PPKR
+kayRCsilTL8sjIwV/XV+XMz/CoUaqwsTsIjZNMY6B6EGPl+3IaOTYF+hvK9Vgft
r1JNET2Igg2hnkRXJyEO4V82Zf1bgTEt0+KBuAGxkT6owRsUMDO3UiRyiC8iYevA
rFwE3xnmMMUO/+AFVDrnuBUnvE8xwQ6zkAlEUt0pT4fI52GlpzLVLA==
-----END CERTIFICATE-----
";

    pub(super) const LEAF: &str = "-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhyc2Et
cm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNTEyMzAwMDAwMDBaMBMxETAPBgNVBAMM
CHJzYS1sZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnchOz3+U
4FF5wSqf6a/zFoTUbC785UIMvOoupyT4RURgm0MfBgumwvshl7oHL1b1JgSRB6jk
Nua0sdNarwHh2XnTVtJfgNl9buvwGE8AQZPiu80ha92ZsjlsFUpVKB/F9PAMpOtz
U/+Z2aRbLKYlCDBNdkOEpIx14FJx16Dywi/kiRhhGbb9uLoZ0bV7gtRkYwBZONTz
ENo92z4ino8Qbiao+QVNqW8iZ1RkYyizOSrrClgi71pyN8GW7CRpH4EluoGrw2Jp
+WNpIi3wqFuYgJ8TCrn5DqZVvBs4pMI9s257XfHFTybspOVpkSNwillbTRT7sU6s
OXizdw+mpkNCxQIDAQABoyUwIzAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQBEUk1TvV0V1EOWpVSj7VN5/xwevy05
A+s7V9J55vXxTaKANlowD/300FtmIBeFtaAPafOvlJfjzWWBdihLf48i5xDxk+C1
sm383htwqq/uckYHs/dmodEcfzbMF+RTpYqc2jVj9V7kHMt15OdpvjSSN6ynRGMM
aMnWKMOSo1mu+ZofASZAnKbiprmo+DqI58/sd5qA49tEIKyK+0CmpKij3k8/RSeL
Kscg06rj5W1i/IN+FmQpmdv8xcojruNePXesS+quPggsnNdXfZCROqQtAI10wxHW
gSSTY3JCP2rcIi/v3XAwY6Bpe5t5k3dWgM81ISCYARnH4wVp39T9g7xn
-----END CERTIFICATE-----
";

    pub(super) const WIDE: &str = "\
-----BEGIN CERTIFICATE-----
MIICxDCCAaygAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhyc2Et
d2lkZTAeFw0yNjAxMDEwMDAwMDBaFw0zNTEyMzAwMDAwMDBaMBMxETAPBgNVBAMM
CHJzYS13aWRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAth5BYKx6
pMqbzAkiVdoRWHs8ZIrOer2AuTLqxgClRK9ngVMyzTFs00AQLHfnD015nXkSXcHw
djseGYoJYCN+Th8fkTPRk0xVvt93KziTD9RcQy//9ucevqYC3nG3Wlu4l3WTY+yD
x+RS3JsV4sh2yDJPQmik02Y74ZLqszL49CgVWGIPvcVXQDP7YJUcOjVnhZ9UyTCk
V7596pRw+rZHbGLwk43qDMO/6+Hgxryr3entoPsPoUOXepuNQOFI45aWz7TpK1Rh
y11tCoUOSdE9cIy15vFezGTHpdGXRYCTf4F4T5vxZsVnl+8aIMJfdkt2tNNIXiyF
xY8hOwCb7me+qQIDAQABoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwICBDANBgkqhkiG9w0BAQsFAAOCAQEABZQ7Sqz6592+Px02ouqh/L2ooUTe+OVC
2QdRS8/tWJ9h25J7cba+lJ3SQbuASZrz8ZcxSmDwi8Z8/uZv6NWc/JlAETqwgqYp
rBbM/MXEpNmYMrBzrZ2rE3Cx+tT1VJISytGSkDdvQYzVSqliBvTBpIbkGpNuZ/wv
PlgQAFEBUAAw/oln2qGxckCtFZgv4sEn51Cle9I3fC2MGhM8KqT+1w8osCg21rVs
/JysazRx2hJZ/Evf3RGkG28pVAogyT7LipJr9gfdH1yPkt4/VRmRkpOg8woSUX2u
+FTGEjESEGfYJ/cW4+1mP+yVt1o2emuzqDY8vnx10Dn1x95PP+ltTw==
-----END CERTIFICATE-----
";

    pub(super) const SHA384: &str = "\
-----BEGIN CERTIFICATE-----
MIICxTCCAa2gAwIBAgIBAjANBgkqhkiG9w0BAQwFADATMREwDwYDVQQDDAhyc2Et
d2lkZTAeFw0yNjAxMDEwMDAwMDBaFw0zNTEyMzAwMDAwMDBaMBIxEDAOBgNVBAMM
B3JzYS0zODQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC8ABece6+
LHanAcoM6LPKgzSJBN4hTVX025SpNj8R0h0oOmYFSVnEZzCYzIVO1jOXOUnHyjwj
tbxt/AT3XWXXoTeb762UwjXicgMj3bkNzQNeBGf0cvt+m6Slm+zqgi06Y++XP29P
9KQ+WMYY8bOJDCmEq7poYelZofLL4/A9E5UPesrL79nD6Wt856CImbDqV8ULkU/K
whcotdJEh5wX5Vi45XiXRv/u3rq3mjb5GgYPCTXZexZGOTDhMrQzUR7VbMHKlk6Z
Sj/pvzmPUq+VAjp1UP9zE93fnpyh34FA1VlXIublTAeBsKLyMXoaFrg/CXqqV2mM
6VbLWsl/8XdTAgMBAAGjJTAjMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDQYJKoZIhvcNAQEMBQADggEBAIdR66m25OZEmr/SoXZ5rw4a6N2FemLq
K4LDxpMvymmj2AzPsZxJaFwUhZiNu64B9VyM/JfzFby6E6o4GDeWTOE9Gi70CjEm
zVy8mx69eMhzz0q5FIOnnLTPi2YgAWBUxm4F5+J4XEewDHtj3rGwc+p5RHffYnJE
cqIkPX/NY1JPtulSYh7HpNJTI7mFnaBtoLYHscJwHY63cMY+heN51TcCNl5mwylF
v7i9/uPDqtsgbKcX7hWzQxOG7OQNzhEgBgDw2wMtoiWTCfk2MF0v0LHQDHz+tEdb
CzUZoT7PtHI7bZzQbUfhqGDQldNrn7p163AuerxxX8+/q7j6KX9ppaw=
-----END CERTIFICATE-----
";

    pub(super) const SHA512: &str = "\
-----BEGIN CERTIFICATE-----
MIICxTCCAa2gAwIBAgIBAzANBgkqhkiG9w0BAQ0FADATMREwDwYDVQQDDAhyc2Et
d2lkZTAeFw0yNjAxMDEwMDAwMDBaFw0zNTEyMzAwMDAwMDBaMBIxEDAOBgNVBAMM
B3JzYS01MTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9H/Zk3dVY
oGYp9nTSwV22ryypAWp1lBRwdLyGO4Pla08qQ0nG1GH0rhxqVTGp2AF4Eryha32b
encCntjjUaUww3oUrL4jL45eAXCPASsRRsZ6yPRSBrEtID+7IPeu3kSTBR8oOokW
XB6GWSjs5Sn7g8cQ9IrsWPC1Rc0cJiS//epd6sjUkSkYylzjoyKglmXBRwzap+ZM
ugq9bgAxY6aGW2y5FUbl5v5fMmN47UxGQ4IcWb1QQDzCU4TF3aqpTxylUq+seEJL
GbvM5JZtWA+fHolalcZwU6KuYLH3mH3rYISD90HdfEipFG1xLvktIqVCHZV1kczQ
ufdONEPv/QXBAgMBAAGjJTAjMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDQYJKoZIhvcNAQENBQADggEBAJsheat0F6lzyzssAmpFC0X0xqK7ZEkt
+a94GC/ZxNyu5JNE8zYkCL2XEo2ASorJjrtMW4OBy50rL+6eggUBlf3aVm8PaHth
RzG1Dngj8FQwNTVu1oZqhYvTelhRTeVdsSmh8KXcIJijO1tDGDQwyzFoaQbyKmRV
HqIEqUBVfTat8yOBUhqklDHRHHHMaXTjv8TSgJkscwwmE9fENxqHntsXfJOoOdTP
vJtJ9YFUExbuS3YMymPgRDA+G/Cxv0Mwj14RW0pgN3kB7jNZm7MrzS3FsPE6W20L
0IPT4xqmt4q9bGIzvANQdnXTkj5CGk9jsP08sRB6IbYUAuXlO5vrc84=
-----END CERTIFICATE-----
";
}
