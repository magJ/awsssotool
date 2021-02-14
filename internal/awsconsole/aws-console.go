package awsconsole

import (
	jsonutil "aws-sso-util/internal/json"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const SigninUrl = "https://signin.aws.amazon.com/federation"
const ConsoleUrl = "https://console.aws.amazon.com/"

type AwsCredentials struct {
	AccessKeyId     string
	Expiration      time.Time
	SecretAccessKey string
	SessionToken    string
}

type IamSessionObject struct {
	SessionId    string
	SessionKey   string
	SessionToken string
}

type IamGetSigninTokenResponse struct {
	SigninToken string
}

func GetConsoleSignInUrl(credentials AwsCredentials, issuer string, desiredDestination string) (string, error) {

	destination := ConsoleUrl
	if desiredDestination != "" {
		_, err := url.ParseRequestURI(desiredDestination)
		if err != nil {
			// Use desired url as-is if parsing succeeds
			destination = desiredDestination
		} else {
			// Assume desired destination is relative, and append to standard console url
			destination = destination + desiredDestination
		}
	}

	iamSessionObject := IamSessionObject{
		SessionId:    credentials.AccessKeyId,
		SessionKey:   credentials.SecretAccessKey,
		SessionToken: credentials.SessionToken,
	}

	serialised, err := json.Marshal(jsonutil.LowerCamelJsonMarshallable{iamSessionObject})
	if err != nil {
		return "", err
	}
	escapedSessionObject := url.QueryEscape(string(serialised))
	getSigninTokenUrl := SigninUrl + "?Action=getSigninToken&Session=" + escapedSessionObject

	get, err := http.Get(getSigninTokenUrl)
	if err != nil {
		return "", err
	}

	all, err := ioutil.ReadAll(get.Body)
	if err != nil {
		return "", nil
	}
	iamGetSigninTokenResponse := IamGetSigninTokenResponse{}

	err = json.Unmarshal(all, &iamGetSigninTokenResponse)
	if err != nil {
		return "", nil
	}

	return SigninUrl +
		"?Action=login" +
		"&Issuer=" + url.QueryEscape(issuer) +
		"&SigninToken=" + iamGetSigninTokenResponse.SigninToken +
		"&Destination=" + url.QueryEscape(destination), nil

}
