package sampler

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
	"crypto/tls"
	"crypto/x509"
)

type Target struct {
	URL      string
	Name     string
	Interval int
	// metadata
	Tags []string
	Attributes map[string]string
}

type Sample struct {
	StatusCode int
	T1         time.Time
	T2         time.Time
}

// Latency returns the amount of milliseconds between T1
// and T2 (start and finish).
func (s Sample) Latency() float64 {
	return s.T2.Sub(s.T1).Seconds() * 1000
}

// StatusCodeError is an error representing an HTTP Status code
// of 400 or greater.
type StatusCodeError struct {
	StatusCode int
}

func (e StatusCodeError) Error() string {
	return fmt.Sprintf(
		"recieved HTTP status %d",
		e.StatusCode,
	)
}

// Sampler implements Sampler, using http.Transport.
type Sampler struct {
	tr        http.Transport
	UserAgent string
}

// New initializes a sane sampler.
func New() Sampler {

	certs := x509.NewCertPool()
	pemPath := "/home/gblmarquez/Downloads/CERTIFICADO_18792479000101.pem"

	fmt.Fprintf(os.Stderr, "read cert %s\n", pemPath)

	pemData, err := ioutil.ReadFile(pemPath)
	if err != nil {
			// do error
	}
	certs.AppendCertsFromPEM(pemData)

	mTLSConfig := &tls.Config {
		RootCAs: roots,
		CipherSuites: []uint16 {
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		}
	}

	mTLSConfig.PreferServerCipherSuites = true
	mTLSConfig.MinVersion = tls.VersionTLS10

	return Sampler{
		tr: http.Transport {
			TLSClientConfig: mTLSConfig,
			DisableKeepAlives: true,
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, 10*time.Second)
				if err != nil {
					return nil, err
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				return c, nil
			},
		},
		UserAgent: "canary / v3",
	}
}

// Sample measures a given target and returns both a Sample and error details.
func (s Sampler) Sample(target Target) (sample Sample, err error) {

	client := &http.Client {
		Transport: s.tr
	}

	req, err := client.Get(target.URL) //http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return sample, err
	}

	req.Header.Add("User-Agent", s.UserAgent)

	sample.T1 = time.Now()
	defer func() { sample.T2 = time.Now() }()

	resp, err := s.tr.RoundTrip(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	sample.StatusCode = resp.StatusCode
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if sample.StatusCode >= 400 {
		err = &StatusCodeError{
			StatusCode: sample.StatusCode,
		}
	}

	return
}
