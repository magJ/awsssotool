package ssooidc

import (
	jsonutil "awsssotool/internal/json"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssoidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type BotoClientRegistration struct {
	ClientId     string
	ClientSecret string
	ExpiresAt    time.Time
}

type BotoAccessTokenCache struct {
	StartUrl    string
	Region      string
	AccessToken string
	ExpiresAt   time.Time
}

type Client struct {
	ssoOidcClient      ssooidc.Client
	region             string
	clientRegistration *BotoClientRegistration
}

func NewClient(cfg aws.Config) Client {
	return Client{
		ssoOidcClient: *ssooidc.NewFromConfig(cfg),
		region:        cfg.Region,
	}
}

func (c *Client) AcquireSsoAuthentication(startUrl string) (*BotoAccessTokenCache, error) {
	log.Debug("Attempting to read boto access token cache")
	accessToken, err := readAccessTokenCache(startUrl)
	if err != nil || accessToken.ExpiresAt.Before(time.Now()) {
		log.Debug("Boto access token cache could not be read, beginning device authorization")
		accessToken, err = c.startAndPollDeviceAuthorisation(startUrl)
		if err != nil {
			return nil, err
		}
		log.Debug("Saving access token to boto cache")
		err = saveAccessTokenCache(*accessToken)
		if err != nil {
			return nil, err
		}
	}
	return accessToken, nil
}

func ReadNonExpiredAccessTokenCache(startUrl string) *BotoAccessTokenCache {
	log.Debug("Attempting to read boto access token cache")
	accessToken, err := readAccessTokenCache(startUrl)
	if err != nil {
		log.Debug("Could not read boto access token cache", err)
		return nil
	}
	if accessToken.ExpiresAt.Before(time.Now()) {
		log.Debug("Boto access token cache expired.")
		return nil
	}
	log.Debug("Boto access token cache loaded.")
	return accessToken
}

func (c *Client) AcquireClientRegistration() (*BotoClientRegistration, error) {
	if c.clientRegistration != nil && isClientRegistrationExpired(c.clientRegistration) {
		return c.clientRegistration, nil
	}
	log.Debug("Attempting to read boto client registration")
	clientRegistration, err := readBotoClientRegistration(c.region)
	if err != nil || isClientRegistrationExpired(clientRegistration) {
		log.Debug("Boto client registration cache could not be read, registering client")
		clientRegistration, err = c.registerBotoClient()
		if err != nil {
			return nil, err
		}
		log.Debug("Saving boto client registration")
		err = saveBotoClientRegistration(c.region, *clientRegistration)
		if err != nil {
			return nil, err
		}
	} else {
		log.Debug("Boto client registration loaded")
	}
	return clientRegistration, nil
}

func isClientRegistrationExpired(clientRegistration *BotoClientRegistration) bool {
	return clientRegistration.ExpiresAt.Before(time.Now())
}

func (c *Client) StartDeviceAuthorisation(startUrl string) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	clientRegistration, err := c.AcquireClientRegistration()
	if err != nil {
		return nil, err
	}
	return c.ssoOidcClient.StartDeviceAuthorization(context.TODO(), &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     &clientRegistration.ClientId,
		ClientSecret: &clientRegistration.ClientSecret,
		StartUrl:     aws.String(startUrl),
	})
}

func (c *Client) startAndPollDeviceAuthorisation(
	startUrl string,
) (*BotoAccessTokenCache, error) {

	startDeviceAuthorizationResponse, err := c.StartDeviceAuthorisation(startUrl)

	if err != nil {
		return nil, err
	}

	log.Println(*startDeviceAuthorizationResponse.VerificationUriComplete)
	log.Println("User code: " + *startDeviceAuthorizationResponse.UserCode)

	createTokenResponse, err := c.PollingDeviceAuthorisation(
		time.Duration(startDeviceAuthorizationResponse.Interval)*time.Second,
		*startDeviceAuthorizationResponse.DeviceCode)
	if err != nil {
		return nil, err
	}

	return c.BuildBotoAccessToken(startUrl, createTokenResponse), nil
}

func (c *Client) BuildAndSaveBotoAccessToken(startUrl string, createTokenResponse *ssooidc.CreateTokenOutput) (*BotoAccessTokenCache, error) {
	token := c.BuildBotoAccessToken(startUrl, createTokenResponse)
	log.Debug("Saving access token to boto cache")
	err := saveAccessTokenCache(*token)
	return token, err
}

func (c *Client) BuildBotoAccessToken(
	startUrl string,
	createTokenResponse *ssooidc.CreateTokenOutput,
) *BotoAccessTokenCache {
	return &BotoAccessTokenCache{
		StartUrl:    startUrl,
		Region:      c.region,
		AccessToken: *createTokenResponse.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(createTokenResponse.ExpiresIn) * time.Second),
	}
}

func (c *Client) PollingDeviceAuthorisation(
	interval time.Duration,
	deviceCode string,
) (*ssooidc.CreateTokenOutput, error) {

	clientRegistration, err := c.AcquireClientRegistration()
	if err != nil {
		return nil, err
	}

	var createTokenResponse *ssooidc.CreateTokenOutput

	for createTokenResponse == nil {
		time.Sleep(interval)
		createTokenResponse, err = c.ssoOidcClient.CreateToken(context.TODO(), &ssooidc.CreateTokenInput{
			ClientId:     &clientRegistration.ClientId,
			ClientSecret: &clientRegistration.ClientSecret,
			DeviceCode:   aws.String(deviceCode),
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})

		if err != nil {
			var oe *ssoidctypes.AuthorizationPendingException
			if errors.As(err, &oe) {
				log.Debug("Awaiting pending auth")
			} else {
				return nil, err
			}
		}
	}

	return createTokenResponse, nil
}

func (c *Client) registerBotoClient() (*BotoClientRegistration, error) {
	registerClientResponse, err := c.ssoOidcClient.RegisterClient(context.TODO(), &ssooidc.RegisterClientInput{
		ClientName: aws.String("magj-awsssotool"),
		ClientType: aws.String("public"),
		Scopes:     nil,
	})
	if err != nil {
		return nil, err
	}

	return &BotoClientRegistration{
		ClientId:     *registerClientResponse.ClientId,
		ClientSecret: *registerClientResponse.ClientSecret,
		ExpiresAt:    time.Unix(registerClientResponse.ClientSecretExpiresAt, 0),
	}, nil

}

func readBotoClientRegistration(region string) (*BotoClientRegistration, error) {
	botoClientCachePath, err := botoClientCachePath(region)
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadFile(botoClientCachePath)
	if err != nil {
		return nil, err
	}
	var botoClientRegistration BotoClientRegistration
	err = json.Unmarshal(bytes, &botoClientRegistration)
	return &botoClientRegistration, err
}

func saveBotoClientRegistration(region string, registration BotoClientRegistration) error {
	botoClientCachePath, err := botoClientCachePath(region)
	if err != nil {
		return err
	}
	return mergeAndSaveJsonFile(botoClientCachePath, jsonutil.LowerCamelJsonMarshallable{registration}, 0600)
}

func saveAccessTokenCache(botoAccessTokenCache BotoAccessTokenCache) error {
	botoAccessTokenCachePath, err := botoAccessTokenCachePath(botoAccessTokenCache.StartUrl)
	if err != nil {
		return err
	}
	return mergeAndSaveJsonFile(botoAccessTokenCachePath, jsonutil.LowerCamelJsonMarshallable{botoAccessTokenCache}, 0600)
}

// Saves the object to the json file, merging with existing values, non-recursively
func mergeAndSaveJsonFile(filename string, object interface{}, perm os.FileMode) error {
	// first serialise object to json
	objectJson, err := json.Marshal(object)
	if err != nil {
		return err
	}
	// then we can convert it into a map representation
	var objectMap map[string]interface{}
	err = json.Unmarshal(objectJson, &objectMap)
	if err != nil {
		return err
	}
	fileBytes, err := ioutil.ReadFile(filename)
	jsonFileMap := make(map[string]interface{})
	if err != nil {
		log.WithField("filename", filename).
			Debug("Could not find existing json file, will be created")
	} else {
		err = json.Unmarshal(fileBytes, &jsonFileMap)
		if err != nil {
			return err
		}
	}
	// Merge the object with the existing file values, non-recursively
	for k, v := range objectMap {
		jsonFileMap[k] = v
	}
	marshalledBytes, err := json.Marshal(jsonFileMap)

	return ioutil.WriteFile(filename, marshalledBytes, perm)
}

func botoClientCachePath(region string) (string, error) {
	ssoCacheDir, err := ssoCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(ssoCacheDir + "/botocore-client-id-" + region + ".json"), nil
}

func readAccessTokenCache(startUrl string) (*BotoAccessTokenCache, error) {
	botoAccessTokenCachePath, err := botoAccessTokenCachePath(startUrl)
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadFile(botoAccessTokenCachePath)
	if err != nil {
		return nil, err
	}
	botoClientRegistration := BotoAccessTokenCache{}
	err = json.Unmarshal(bytes, &botoClientRegistration)
	return &botoClientRegistration, err
}

func botoAccessTokenCachePath(startUrl string) (string, error) {
	ssoCacheDir, err := ssoCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(ssoCacheDir + "/" + hashUrl(startUrl) + ".json"), nil
}

func ssoCacheDir() (string, error) {
	awsConfigDir, err := awsConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(awsConfigDir + "/sso/cache/"), nil
}

func awsConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(home + "/.aws/"), err
}

func hashUrl(startUrl string) string {
	hash := sha1.Sum([]byte(startUrl))
	return fmt.Sprintf("%x", hash)
}
