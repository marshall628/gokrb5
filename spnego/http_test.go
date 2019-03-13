package spnego

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/test"
	"gopkg.in/jcmturner/gokrb5.v7/test/testdata"
)

func TestClient_SetSPNEGOHeader(t *testing.T) {
	test.Integration(t)
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}
	paths := []string{
		"/modkerb/index.html",
		//"/modgssapi/index.html",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest("GET", url+p, nil)
			httpResp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v", url+p, err)
			}
			assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")

			err = SetSPNEGOHeader(cl, r, "")
			if err != nil {
				t.Fatalf("error setting client SPNEGO header: %v", err)
			}

			httpResp, err = http.DefaultClient.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v\n", url+p, err)
			}
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
		}
	}
}

func TestSPNEGOHTTPClient(t *testing.T) {
	test.Integration(t)
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}
	urls := []string{
		"http://cname.test.gokrb5",
		"http://host.test.gokrb5",
	}
	// This path issues a redirect which the http client will automatically follow.
	// It should cause a replay issue if the negInit token is sent in the first instance.
	paths := []string{
		"/modgssapi", // This issues a redirect which the http client will automatically follow. Could cause a replay issue
		"/redirect",
	}
	for _, url := range urls {
		for _, p := range paths {
			r, _ := http.NewRequest("GET", url+p, nil)
			httpCl := http.DefaultClient
			httpCl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				t.Logf("http client redirect: %+v", *req)
				return nil
			}
			spnegoCl := NewClient(cl, httpCl, "")
			httpResp, err := spnegoCl.Do(r)
			if err != nil {
				t.Fatalf("%s request error: %v", url+p, err)
			}
			assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
		}
	}
}

func TestService_SPNEGOKRB_NoAuthHeader(t *testing.T) {
	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected")
	assert.Equal(t, "Negotiate", httpResp.Header.Get("WWW-Authenticate"), "Negitation header not set by server.")
}

func TestService_SPNEGOKRB_ValidUser(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")
}

func TestService_SPNEGOKRB_Replay(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r1, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// First request with this ticket should be accepted
	httpResp, err := http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Use ticket again should be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Form a 2nd ticket
	r2, _ := http.NewRequest("GET", s.URL, nil)

	err = SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// First use of 2nd ticket should be accepted
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "Status code in response to client SPNEGO request not as expected")

	// Using the 1st ticket again should still be rejected
	httpResp, err = http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")

	// Using the 2nd again should be rejected as replay
	httpResp, err = http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpResp.StatusCode, "Status code in response to client with no SPNEGO not as expected. Expected a replay to be detected.")
}

func TestService_SPNEGOKRB_ReplayCache_Concurrency(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()
	r1, _ := http.NewRequest("GET", s.URL, nil)

	cl := getClient()
	err := SetSPNEGOHeader(cl, r1, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	r2, _ := http.NewRequest("GET", s.URL, nil)

	err = SetSPNEGOHeader(cl, r2, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	// Concurrent 1st requests should be OK
	var wg sync.WaitGroup
	wg.Add(2)
	go httpGet(r1, &wg)
	go httpGet(r2, &wg)
	wg.Wait()

	// A number of concurrent requests with the same ticket should be rejected due to replay
	var wg2 sync.WaitGroup
	noReq := 10
	wg2.Add(noReq * 2)
	for i := 0; i < noReq; i++ {
		go httpGet(r1, &wg2)
		go httpGet(r2, &wg2)
	}
	wg2.Wait()
}

func TestService_SPNEGOKRB_Upload(t *testing.T) {
	test.Integration(t)

	s := httpServer()
	defer s.Close()

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", "testfile.bin")
	if err != nil {
		t.Fatalf("error writing to buffer: %v", err)
	}

	data := make([]byte, 10240)
	rand.Read(data)
	br := bytes.NewReader(data)
	_, err = io.Copy(fileWriter, br)
	if err != nil {
		t.Fatalf("error copying bytes: %v", err)
	}
	bodyWriter.Close()

	r, _ := http.NewRequest("POST", s.URL, bodyBuf)

	cl := getClient()
	err = SetSPNEGOHeader(cl, r, "HTTP/host.test.gokrb5")
	if err != nil {
		t.Fatalf("error setting client's SPNEGO header: %v", err)
	}

	r.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	httpResp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("Request error: %v\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(httpResp.Body)
		bodyString := string(bodyBytes)
		httpResp.Body.Close()
		t.Errorf("unexpected code from http server (%d): %s", httpResp.StatusCode, bodyString)
	}
}

func TestService_SPNEGO_ADService(t *testing.T) {
	test.AD(t)

	s := httpServerAD()
	defer s.Close()
	r, _ := http.NewRequest("GET", s.URL, nil)

	b, _ := hex.DecodeString(testdata.TESTUSER1_USERKRB5_AD_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	l := log.New(os.Stderr, "SPNEGO Client:", log.LstdFlags)
	cl := client.NewClientWithKeytab("testuser1", "USER.GOKRB5", kt, c, client.Logger(l))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on AS_REQ: %v\n", err)
	}

	spnegoCl := NewClient(cl, nil, "HTTP/user2.user.gokrb5")
	resp, err := spnegoCl.Do(r)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Email: testuser1@email.user.gokrb5") {
		t.Error("email address from claims info not returned")
	}
}

func httpGet(r *http.Request, wg *sync.WaitGroup) {
	defer wg.Done()
	http.DefaultClient.Do(r)
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	return s
}

func httpServerAD() *httptest.Server {
	//SPN HTTP/user2.user.gokrb5 registered against testuser2@USER.GOKRB5
	l := log.New(os.Stderr, "GOKRB5 AD Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, _ := hex.DecodeString(testdata.TESTUSER2_USERKRB5_AD_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	th := http.HandlerFunc(testAppHandler)
	//TODO the test server set up is impacted by https://github.com/jcmturner/gokrb5/issues/275
	s := httptest.NewServer(SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.KeytabPrincipal("testuser2")))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		maxUploadSize := int64(11240)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			http.Error(w, fmt.Sprintf("cannot parse multipart form: %v", err), http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		file, _, err := r.FormFile("uploadfile")
		if err != nil {
			http.Error(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// write out to /dev/null
		_, err = io.Copy(ioutil.Discard, file)
		if err != nil {
			http.Error(w, "WRITE_ERR", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	creds := ctx.Value(CTXKeyCredentials).(goidentity.Identity)
	var email string
	if mail, ok := creds.Attributes()["mail"].([]string); ok {
		email = mail[0]
	}
	fmt.Fprintf(w,
		`<html>
<h1>GOKRB5 Handler</h1>
<ul>
<li>Authenticed user: %s</li>
<li>User's realm: %s</li>
<li>Authn time: %v</li>
<li>Session ID: %s</li>
<li>Email: %+v</li>
<ul>
</html>`,
		creds.UserName(),
		creds.Domain(),
		creds.AuthTime(),
		creds.SessionID(),
		email,
	)
	return
}

func getClient() *client.Client {
	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	c.LibDefaults.NoAddresses = true
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.TEST_KDC_ADDR
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.TEST_KDC}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	return cl
}
