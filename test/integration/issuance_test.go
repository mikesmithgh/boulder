//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

// TestCommonNameInCSR ensures that CSRs which have a CN set result in certs
// with the same CN set.
func TestCommonNameInCSR(t *testing.T) {
	t.Parallel()

	// Create an account.
	os.Setenv("DIRECTORY", "http://boulder.service.consul:4001/directory")
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Put together some names.
	cn := random_domain()
	san1 := random_domain()
	san2 := random_domain()

	// Issue a cert. authAndIssue includes the 0th name as the CN by default.
	ir, err := authAndIssue(client, key, []string{cn, san1, san2}, true)
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the CN is incorporated into the SANs.
	test.AssertSliceContains(t, cert.DNSNames, cn)
	test.AssertSliceContains(t, cert.DNSNames, san1)
	test.AssertSliceContains(t, cert.DNSNames, san2)

	// Ensure that the CN is preserved as the CN.
	test.AssertEquals(t, cert.Subject.CommonName, cn)
}

// TestCommonNameHoisted ensures that CSRs which have no CN set result in certs
// with one of their SANs hoisted into the CN field.
func TestCommonNameHoisted(t *testing.T) {
	t.Parallel()

	// Create an account.
	os.Setenv("DIRECTORY", "http://boulder.service.consul:4001/directory")
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Put together some names.
	san1 := random_domain()
	san2 := random_domain()

	// Issue a cert using a CSR with no CN set.
	ir, err := authAndIssue(client, key, []string{san1, san2}, false)
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the SANs are correct.
	test.AssertSliceContains(t, cert.DNSNames, san1)
	test.AssertSliceContains(t, cert.DNSNames, san2)

	// Ensure that one of the SANs is the CN.
	test.Assert(t, cert.Subject.CommonName == san1 || cert.Subject.CommonName == san2, "SAN should have been hoisted")
}

// TestCommonNameSANsTooLong tests that, when the names in an order and CSR are
// too long to be hoisted into the CN, the correct behavior results (depending
// on the state of the RequireCommonName feature flag).
func TestCommonNameSANsTooLong(t *testing.T) {
	t.Parallel()

	// Create an account.
	os.Setenv("DIRECTORY", "http://boulder.service.consul:4001/directory")
	client, err := makeClient("mailto:example@letsencrypt.org")
	test.AssertNotError(t, err, "creating acme client")

	// Create a private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// Put together some names.
	san1 := fmt.Sprintf("thisdomainnameis.morethan64characterslong.forthesakeoftesting.%s", random_domain())
	san2 := fmt.Sprintf("thisdomainnameis.morethan64characterslong.forthesakeoftesting.%s", random_domain())

	// Issue a cert using a CSR with no CN set.
	ir, err := authAndIssue(client, key, []string{san1, san2}, false)

	// By default, the RequireCommonName flag is true, so issuance should have failed.
	if !strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		test.AssertError(t, err, "issuing cert with no CN")
		return
	}

	// But in config-next, the RequireCommonName flag is false, so issuance should
	// have succeeded.
	test.AssertNotError(t, err, "failed to issue test cert")
	cert := ir.certs[0]

	// Ensure that the SANs are correct.
	test.AssertSliceContains(t, cert.DNSNames, san1)
	test.AssertSliceContains(t, cert.DNSNames, san2)

	// Ensure that the CN is empty.
	test.AssertEquals(t, cert.Subject.CommonName, "")
}
