[ -d "target/tmp/pki-test-framework" ] || exit 0

cd target/tmp/pki-test-framework

docker compose down -t 5

cd ..
rm -fr pki-test-framework