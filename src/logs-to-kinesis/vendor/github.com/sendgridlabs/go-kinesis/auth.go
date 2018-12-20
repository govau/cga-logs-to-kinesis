package kinesis

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	AccessEnvKey        = "AWS_ACCESS_KEY"
	AccessEnvKeyId      = "AWS_ACCESS_KEY_ID"
	SecretEnvKey        = "AWS_SECRET_KEY"
	SecretEnvAccessKey  = "AWS_SECRET_ACCESS_KEY"
	SecurityTokenEnvKey = "AWS_SECURITY_TOKEN"

	AWSMetadataServer = "169.254.169.254"
	AWSIAMCredsPath   = "/latest/meta-data/iam/security-credentials"
	AWSIAMCredsURL    = "http://" + AWSMetadataServer + "/" + AWSIAMCredsPath

	AWSSecurityTokenHeader = "X-Amz-Security-Token"
)

// Auth interface for authentication credentials and information
type Auth interface {
	KeyForSigning(now time.Time) (*SigningKey, error)
}

type SigningKey struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string

	Expiration time.Time
}

func (sc *SigningKey) KeyForSigning(now time.Time) (*SigningKey, error) {
	return sc, nil
}

// NewAuth creates a *AuthCredentials struct that adheres to the Auth interface to
// dynamically retrieve AWS credentials
func NewAuth(accessKey, secretKey, token string) Auth {
	return &SigningKey{
		AccessKeyId:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    token,
	}
}

// NewAuthFromEnv retrieves auth credentials from environment vars
func NewAuthFromEnv() (Auth, error) {
	accessKey := os.Getenv(AccessEnvKey)
	if accessKey == "" {
		accessKey = os.Getenv(AccessEnvKeyId)
	}

	secretKey := os.Getenv(SecretEnvKey)
	if secretKey == "" {
		secretKey = os.Getenv(SecretEnvAccessKey)
	}

	token := os.Getenv(SecurityTokenEnvKey)

	if accessKey == "" && secretKey == "" && token == "" {
		return nil, fmt.Errorf("No access key (%s or %s), secret key (%s or %s), or security token (%s) env variables were set", AccessEnvKey, AccessEnvKeyId, SecretEnvKey, SecretEnvAccessKey, SecurityTokenEnvKey)
	}
	if accessKey == "" {
		return nil, fmt.Errorf("Unable to retrieve access key from %s or %s env variables", AccessEnvKey, AccessEnvKeyId)
	}
	if secretKey == "" {
		return nil, fmt.Errorf("Unable to retrieve secret key from %s or %s env variables", SecretEnvKey, SecretEnvAccessKey)
	}

	return NewAuth(accessKey, secretKey, token), nil
}

type cachedMutexedAuth struct {
	mu         sync.Mutex
	current    *SigningKey
	underlying Auth
}

func newCachedMutexedWarmedUpAuth(underlying Auth) (Auth, error) {
	rv := &cachedMutexedAuth{
		underlying: underlying,
	}
	_, err := rv.KeyForSigning(time.Now())
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (cmuxa *cachedMutexedAuth) KeyForSigning(now time.Time) (*SigningKey, error) {
	cmuxa.mu.Lock()
	defer cmuxa.mu.Unlock()

	if cmuxa.current == nil || !cmuxa.current.Expiration.After(now) {
		newSK, err := cmuxa.underlying.KeyForSigning(now)
		if err != nil {
			return nil, err
		}
		cmuxa.current = newSK
	}

	return cmuxa.current, nil
}

type metadataCreds struct{}

func (mc *metadataCreds) KeyForSigning(now time.Time) (*SigningKey, error) {
	role, err := retrieveIAMRole()
	if err != nil {
		return nil, err
	}

	data, err := retrieveAWSCredentials(role)
	if err != nil {
		return nil, err
	}

	// Ignore the error, it just means we won't be able to refresh the
	// credentials when they expire.
	expiry, _ := time.Parse(time.RFC3339, data["Expiration"])

	return &SigningKey{
		AccessKeyId:     data["AccessKeyId"],
		SecretAccessKey: data["SecretAccessKey"],
		SessionToken:    data["Token"],
		Expiration:      expiry,
	}, nil
}

// NewAuthFromMetadata retrieves auth credentials from the metadata
// server. If an IAM role is associated with the instance we are running on, the
// metadata server will expose credentials for that role under a known endpoint.
//
// TODO: specify custom network (connect, read) timeouts, else this will block
// for the default timeout durations.
func NewAuthFromMetadata() (Auth, error) {
	return newCachedMutexedWarmedUpAuth(&metadataCreds{})
}

func retrieveAWSCredentials(role string) (map[string]string, error) {
	var bodybytes []byte
	// Retrieve the json for this role
	resp, err := http.Get(fmt.Sprintf("%s/%s", AWSIAMCredsURL, role))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, err
	}
	defer resp.Body.Close()

	bodybytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	jsondata := make(map[string]string)
	err = json.Unmarshal(bodybytes, &jsondata)
	if err != nil {
		return nil, err
	}

	return jsondata, nil
}

func retrieveIAMRole() (string, error) {
	var bodybytes []byte

	resp, err := http.Get(AWSIAMCredsURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", err
	}
	defer resp.Body.Close()

	bodybytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// pick the first IAM role
	role := strings.Split(string(bodybytes), "\n")[0]
	if len(role) == 0 {
		return "", errors.New("Unable to retrieve IAM role")
	}

	return role, nil
}

type stsCreds struct {
	RoleARN   string
	Region    string
	OtherAuth Auth
}

func (sts *stsCreds) KeyForSigning(now time.Time) (*SigningKey, error) {
	r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://sts.%s.amazonaws.com/?%s", sts.Region, (url.Values{
		"Version":         []string{"2011-06-15"},
		"Action":          []string{"AssumeRole"},
		"RoleSessionName": []string{"kinesis"},
		"RoleArn":         []string{sts.RoleARN},
	}).Encode()), nil)
	if err != nil {
		return nil, err
	}

	err = (&Service{
		Name:   "sts",
		Region: sts.Region,
	}).Sign(sts.OtherAuth, r)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code")
	}

	var wrapper struct {
		AssumeRoleResult struct {
			Credentials *SigningKey
		}
	}
	err = xml.NewDecoder(resp.Body).Decode(&wrapper)
	if err != nil {
		return nil, err
	}

	if wrapper.AssumeRoleResult.Credentials == nil {
		return nil, errors.New("bad data back")
	}

	return wrapper.AssumeRoleResult.Credentials, nil
}

// NewAuthWithAssumedRole will call STS in a given region to assume a role
func NewAuthWithAssumedRole(roleArn, region string, otherAuth Auth) (Auth, error) {
	return newCachedMutexedWarmedUpAuth(&stsCreds{
		RoleARN:   roleArn,
		Region:    region,
		OtherAuth: otherAuth,
	})
}
