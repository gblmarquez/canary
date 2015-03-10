package manifest

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gblmarquez/canary/pkg/sampler"
)

// Manifest represents configuration data.
type Manifest struct {
	Targets     []sampler.Target
	StartDelays []float64
}

// GenerateRampupDelays generates an even distribution of sensor start delays
// based on the passed number of interval seconds and the number of targets.
func (m *Manifest) GenerateRampupDelays(intervalSeconds int) {
	var intervalMilliseconds = float64(intervalSeconds * 1000)

	var chunkSize = float64(intervalMilliseconds / float64(len(m.Targets)))

	for i := 0.0; i < intervalMilliseconds; i = i + chunkSize {
		m.StartDelays[int((i / chunkSize))] = i
	}
}

// GetManifest retreives a manifest from a given URL.
func GetManifest(url string, defaultInterval int) (manifest Manifest, err error) {
	var stream io.ReadCloser

	if url[:7] == "file://" {
		stream, err = os.Open(url[7:])
	} else {
		resp, e := http.Get(url)
		err = e
		if err != nil {
			return
		}

		stream = resp.Body
	}

	defer stream.Close()

	body, err := ioutil.ReadAll(stream)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &manifest)
	if err != nil {
		return
	}

	// Determine whether to use target.Interval or defaultInterval
	// Targets that lack an interval value in JSON will have their value set to zero. in this case,
	// use defaultInterval
	for ind := range manifest.Targets {
		if manifest.Targets[ind].Interval == 0 {
			manifest.Targets[ind].Interval = defaultInterval
		}
	}

	// Initialize manifest.StartDelays to zeros
	manifest.StartDelays = make([]float64, len(manifest.Targets))
	for i := 0; i < len(manifest.Targets); i++ {
		manifest.StartDelays[i] = 0.0
	}

	return
}
