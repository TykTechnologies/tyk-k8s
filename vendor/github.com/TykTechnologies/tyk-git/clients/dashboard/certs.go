package dashboard

import (
	"bytes"
	"fmt"
	"github.com/levigross/grequests"
	"github.com/ongoingio/urljoin"
	"io/ioutil"
	"strings"
)

func (c *Client) CreateCertificate(cert []byte) (string, error) {
	fullPath := urljoin.Join(c.url, endpointCerts)

	ro := &grequests.RequestOptions{
		Files: []grequests.FileUpload{
			{
				FileContents: ioutil.NopCloser(bytes.NewReader(cert)),
			},
		},
		Headers: map[string]string{
			"Authorization": c.secret,
		},
	}

	resp, err := grequests.Post(fullPath, ro)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API Returned error: %v", resp.String())
	}

	dbResp := CertResponse{}
	if err := resp.JSON(&dbResp); err != nil {
		return "", err
	}

	if strings.ToLower(dbResp.Status) != "ok" {
		return "", fmt.Errorf("API request completed, but with error: %v", dbResp.Message)
	}

	return dbResp.Id, nil
}
