package certs

//Sample certificates
func getMicrosoftRootCert() (output []byte) {
	output = []byte(`
-----BEGIN CERTIFICATE-----
MIIDvDCCAqSgAwIBAgIQRu1aq2iixptJxn4zjSe48jANBgkqhkiG9w0BAQ0FADBQ
MRMwEQYKCZImiZPyLGQBGRYDbmV0MRkwFwYKCZImiZPyLGQBGRYJYXZ4ZGV2bGFi
MR4wHAYDVQQDExVhdnhkZXZsYWItQVZYRU5UQ0EtQ0EwHhcNMTgwOTA1MDg1NjA1
WhcNMjMwOTA1MDkwNjAzWjBQMRMwEQYKCZImiZPyLGQBGRYDbmV0MRkwFwYKCZIm
iZPyLGQBGRYJYXZ4ZGV2bGFiMR4wHAYDVQQDExVhdnhkZXZsYWItQVZYRU5UQ0Et
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbQ+rvOpKsvVE3Mqj7
+rjIMoKOhrag+hSMzxxcSKo3USOm7smMeSnyLBbkVqjJ+SrL1mYi7KssqFmNisKS
LA+vy0tqBYr6wcmy03qVmNt8coX78XjNIouqBDGJ0sosrdh+MGYKY3g1kBURry43
n0kGyy/KBDebsTcWeb25Y1h54bHJ7Buxvoq+JrdejPk/d/VI65V51DUAEKpdjpuY
kScDMictDS8FC9XoZCqNoY62yBtfr818Cid1hPthEpfN4B8v3Xx9Rx8hPkMArNt6
pJbwj/RdNSf+Gu+mo0tvx53tsnsh9fGtl9RSYlnjXyn+eJyNVRlBNiaH3beWqp+8
IcJnAgMBAAGjgZEwgY4wEwYJKwYBBAGCNxQCBAYeBABDAEEwDgYDVR0PAQH/BAQD
AgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFBY6a3mEuK53JzwR+dN5f+DJ
qFDuMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFGotgtHQNTe2
nQQANAXOaA4IQEPGMA0GCSqGSIb3DQEBDQUAA4IBAQCQEy9eii2/2eFwicVAPjD2
yIb5L845WpiR21DK97MHaznFGWM39vMnX+ac0Ycwo06kZ5W5trIC20s7cgrcqm6u
u3hdI19+xuijpG+BkodWyQfln4fKGvZsv/pOzoSn6alIPz0vxfKcHsdy/1bFCZe9
d4aIbX67zXgVaTGRWKW7VeW/ffGqWfREC8RevjVHJCYqIQp9e30SMx3dH5SXpsX/
1dAVvuNbyu5sEXLTBhO0U2Q1iEYNojpV1D8YZiZZCbRsEeRd3RlaXeJizfW2WVgp
iyt4D0r6H693Op3ACm6PPA/tarympSXr7t0vKGTti0qO854aKxAldNAfYMdp+TLc
-----END CERTIFICATE-----`)
	return
}

func getMicrosoftInterMediateCert() (output []byte) {
	output = []byte(`
-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgITNwAApmgffg+abkDY4AABAACmaDANBgkqhkiG9w0BAQsF
ADBQMRMwEQYKCZImiZPyLGQBGRYDbmV0MRkwFwYKCZImiZPyLGQBGRYJYXZ4ZGV2
bGFiMR4wHAYDVQQDExVhdnhkZXZsYWItQVZYRU5UQ0EtQ0EwHhcNMTkxMjEzMDMx
OTE2WhcNMjExMjEzMDMyOTE2WjBXMRMwEQYKCZImiZPyLGQBGRYDbmV0MRkwFwYK
CZImiZPyLGQBGRYJYXZ4ZGV2bGFiMSUwIwYDVQQDExxhdnhkZXZsYWItQVZYU1JW
MDItQ0EtU0hBMzg0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtLJF
c+cA5J7r3JBpkNPVC/sTXAs4o00dmJ29OJXe6IIw1k+D2FKdpM3fxhd6Um3I2Jar
TjN2dYiemDKvLU0aWM/RUS0nx6QPW4UO1ulvizPrqu5Ft45n6uCKMQa+kJCJIWXS
dFpsDD7hvifg/nq3bWY1pbY+P0WzPrs2d3DwZJ4EjAfEtFDFTR8uXeM56NMUWoRB
H+oOOPJG0D1IHtCHfpz1Oc1pi9jBpwZ/TA7g/gOf0GSJRqKM/EdrxcpFhKHiBcaW
QZqr+zyLPtfkcVi/Hk2eZNiTLFrpenkOdHB6c9UYmrcKhazPGctJ6JEn6ni7Su4l
IDbAUv/2wRJrknmXhQIDAQABo4IBLzCCASswEAYJKwYBBAGCNxUBBAMCAQEwIwYJ
KwYBBAGCNxUCBBYEFAwaUjFN1nMqN+faOE/zRRofDmLCMB0GA1UdDgQWBBTsesvm
3m71PCuvSPiar9kvBFfpAzAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAOBgNV
HQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQWOmt5hLiu
dyc8EfnTeX/gyahQ7jBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8vMTAuMTAuMTAw
LjE2MjoxMjUwL2F2eGRldmxhYi1BVlhFTlRDQS1DQS5jcmwwMAYIKwYBBQUHAQEE
JDAiMCAGCCsGAQUFBzABhhRodHRwOi8vMTAuMTAuMTAwLjE2MjANBgkqhkiG9w0B
AQsFAAOCAQEAMcDGyf28v6hjk4l4oXWnUYka/pxuXMm6UZpSYzocrc8Ln1Qk1bv1
+jk6jz91X0tXJH3lY9KRx798oEqHcKAppOMVe6+Ldyevm434Ul1B75sxW3qmjdn0
tIMLvG2zSfWjY3IeZeTDWwKs4XYLL0/PYJHOYX+Gfw3/RzufTDNbm9qArPCH4rF6
BXw4K+b0znrFmHZL4HhrvOoyaHcTwRNzHzG+xRihrzToyz18VAJ8ptI6+/Q8G1tW
Etg5rFxjcSy/a+RtrZkDdQhWL3eUQC5t7RvOHuq5zt6MrNd3ge8ojW6IwuQaDTy+
IodYaPaXdja44V8oFUv2dSdUM+TxHlyXGQ==
-----END CERTIFICATE-----`)
	return
}

func getMicrosoftInterMediateKey() (output []byte) {
	output = []byte(``)
	return
}