[ -d "target/tmp/pki-test-framework" ] && exit 0;

mkdir -p target/tmp
cd target/tmp

git clone --depth 1 --branch v0.2.2 https://github.com/merlincinematic/pki-test-framework.git pki-test-framework
cd pki-test-framework

docker compose build --no-cache --build-arg AIA_URL_SERVER_PORT

docker compose up --detach --wait --wait-timeout 5

docker compose exec identity /root.sh -t > root.pem

 curl --cacert root.pem https://identity.ciph.xxx:4443/certificates/identity.tar.gz |
tar xzv -

