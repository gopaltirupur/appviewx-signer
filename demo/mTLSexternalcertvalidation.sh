# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 1.	create foo namespace

kubectl create namespace foo

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 2.	Enable strict peer authentication mode for the namespace foo

kubectl apply -n foo -f - <<EOF 
apiVersion: "security.istio.io/v1beta1" 
kind: "PeerAuthentication" 
metadata: 
  name: "default" 
spec: 
  mtls: 
    mode: STRICT 
EOF

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 3.	check peerauthentication

kubectl get peerauthentication --all-namespaces

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 4. install sample applications

kubectl apply -f <(getistio istioctl kube-inject -f $(pwd)"/httpbin.yaml") -n foo

kubectl apply -f <(getistio istioctl kube-inject -f $(pwd)"/sleep.yaml") -n foo

sleep 1m

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 5.	*** Wait for side-car injection in "httpbin" and "sleep" pods at foo *** 2/2

kubectl get pods -A;

kubectl describe pod "$(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name})" -n foo | grep Ready;

kubectl describe pod "$(kubectl get pod -l app=httpbin -n foo -o jsonpath={.items..metadata.name})" -n foo | grep Ready;

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 6.	clean tmp folders

rm -rf /tmp/test001/;mkdir /tmp/test001

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 7.	get certificates

kubectl exec "$(kubectl get pod -l app=sleep -n foo -o jsonpath={.items..metadata.name})" -c istio-proxy -n foo -- openssl s_client   -CAfile /run/secrets/istio/root-cert.pem -showcerts -connect httpbin.foo:8000 > /tmp/test001/httpbin-proxy-cert.txt

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Retrieve certificates from the response 	

cd /tmp/test001

sed -n '/-----BEGIN CERTIFICATE-----/{:start /-----END CERTIFICATE-----/!{N;b start};/.*/p}' httpbin-proxy-cert.txt > certs.pem	

cat ./certs.pem

awk 'BEGIN {counter=0;} /BEGIN CERT/{counter++} { print > "proxy-cert-" counter ".pem"}' < certs.pem

# Verify the "root-cert.pem","cert-chain.pem" and the "server-certificate" path

openssl verify -CAfile <(cat ./proxy-cert-2.pem ./proxy-cert-3.pem) ./proxy-cert-1.pem

# View serial number of "httpbin" http response certificate

openssl x509 -noout -serial -in /tmp/test001/proxy-cert-1.pem

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
