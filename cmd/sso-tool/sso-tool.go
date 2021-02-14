package main

import (
	"aws-sso-util/internal/awsconsole"
	"aws-sso-util/internal/config"
	"aws-sso-util/internal/sso"
	"aws-sso-util/internal/ssooidc"
	"context"
	"errors"
	"github.com/AlecAivazis/survey/v2"
	"github.com/TimSatke/stringset"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"github.com/urfave/cli/v2"
	"gopkg.in/ini.v1"
	"hash/adler32"
	"net/url"
	"os"
	"strings"
	"time"
)

var awsLogging aws.ClientLogMode
var cfg config.Context

func main() {
	var app = &cli.App{
		Name:        "sso-tool",
		Description: "The missing AWS SSO cli tool",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v", "debug"},
				Usage:   "Debug level logging",
			},
			&cli.BoolFlag{
				Name:  "trace",
				Usage: "Trace level logging",
			},
			&cli.BoolFlag{
				Name:  "silent",
				Usage: "Disable logging (panic level)",
			},
			&cli.BoolFlag{
				Name:  "quiet",
				Usage: "Less logging (warn level)",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "configure",
				Usage:  "Interactive configuration of various tool options.",
				Action: configureAction,
			},
			{
				Name:  "login",
				Usage: "Acquires AWS SSO device authorisation, opens a browser to SSO CLI auth page if necessary.",
				Description: "Checks for existing valid authorisation.\n" +
					"Performs client registration, and device authorisation via the AWS SSO website.\n" +
					"You will need to login to the website, possibly enter a code, and click the CLI grant confirmation.\n" +
					"This command does pretty much the same thing as aws-cli-v2 `aws sso login`",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  config.NoOpen.Name(),
						Usage: "Just print AWS SSO url, do not open in browser.",
					},
					&cli.StringFlag{
						Name: config.StartUrl.Name(),
						Usage: "URL to AWS SSO start page.\n" +
							"If not specified, we will attempt to discover it from AWS config.",
					},
					&cli.BoolFlag{
						Name:  config.IgnoreCachedAccessToken.Name(),
						Usage: "Ignore cached SSO access token, and forcefully fetch new one",
					},
				},
				Action: loginAction,
			},
			{
				Name:  "sync",
				Usage: "Converts and saves SSO credentials into a format understood by most tools",
				Description: "Tools like AWS CLI v1, AWS CDK and various others, " +
					"are unable to use credentials from the AWS CLI v2 SSO cache.\n" +
					"This command saves role credentials to $HOME/.aws/credentials, in standard format" +
					"(aws_access_key_id, aws_access_access_key, aws_session_token)",
				Action: syncCredentialsAction,
			},
			{
				Name:  "console",
				Usage: "Login to the AWS web console",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: config.StartUrl.Name(),
						Usage: "URL to AWS SSO start page.\n" +
							"If not specified, we will attempt to discover it from AWS config.",
					},
					&cli.StringFlag{
						Name:        config.Destination.Name(),
						Usage:       "The destination page, in the AWS console, to direct to once logged in.",
						DefaultText: awsconsole.ConsoleUrl,
					},
					&cli.BoolFlag{
						Name:  config.NoOpen.Name(),
						Usage: "Just print the console sign-in URL, do not open.",
					},
					&cli.BoolFlag{
						Name:  config.UseBrowserContainer.Name(),
						Usage: "Generate URL compatible with firefox `open-url-in-container` plugin",
					},
				},
				Action: consoleLoginAction,
			},
		},
		Before:  beforeAction,
		Authors: []*cli.Author{{Name: "magJ"}},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func configureAction(c *cli.Context) error {
	return errors.New("command not implemented")
}

func beforeAction(c *cli.Context) error {
	configureLogging(*c)
	awscfg, err := ssoClientAwsConfig()
	if err != nil {
		return err
	}
	cfg = config.NewConfigContext(c, *awscfg)
	return nil
}

func loginAction(c *cli.Context) error {
	cfg.SetCommandContext(c)
	authentication, err, cached := acquireSsoAuthentication()
	if err != nil {
		return err
	}
	if cached {
		log.Info("Using cached credentials for " + authentication.StartUrl)
	} else {
		log.Info("Logged into " + authentication.StartUrl)
	}

	expiresAtWithoutNano := time.Unix(authentication.ExpiresAt.Unix(), 0)
	durationUntilExpiry := expiresAtWithoutNano.Sub(time.Unix(time.Now().Unix(), 0))

	log.Info("Credentials expire at: " + expiresAtWithoutNano.String() + " (" + durationUntilExpiry.String() + ")")
	return nil
}

func syncCredentialsAction(c *cli.Context) error {
	cfg.SetCommandContext(c)
	authentication, err, _ := acquireSsoAuthentication()
	if err != nil {
		return err
	}

	ssoClient := sso.NewClient(cfg.AwsConfig(), authentication.AccessToken)
	listedAccounts, err := ssoClient.ListAccounts()
	if err != nil {
		return err
	}

	var accountsToLoad = accountsToLoad(listedAccounts)

	for _, accountId := range accountsToLoad {
		roles, err := ssoClient.ListAccountRoles(accountId)
		if err != nil {
			return err
		}
		rolesToLoad := rolesToLoad(accountId, roles)
		for _, role := range rolesToLoad {
			credentials, err := ssoClient.GetRoleCredentials(accountId, role)
			if err != nil {
				return err
			}
			saveProfileCredentials(accountId, role, *credentials)
		}
	}
	return nil
}

type accountUrlDetail struct {
	consoleUrl  string
	roleName    string
	accountInfo types.AccountInfo
}

func consoleLoginAction(c *cli.Context) error {
	cfg.SetCommandContext(c)
	authentication, err, _ := acquireSsoAuthentication()
	if err != nil {
		return err
	}

	ssoClient := sso.NewClient(cfg.AwsConfig(), authentication.AccessToken)
	listedAccounts, err := ssoClient.ListAccounts()
	if err != nil {
		return err
	}

	var accountMap = make(map[string]types.AccountInfo)
	for _, account := range listedAccounts {
		accountMap[*account.AccountId] = account
	}

	var accountsToLoad = accountsToLoad(listedAccounts)

	if len(accountsToLoad) == 0 {
		log.Info("No accounts selected")
		return nil
	}

	var accountUrlDetails []accountUrlDetail

	for _, accountId := range accountsToLoad {
		roles, err := ssoClient.ListAccountRoles(accountId)
		if err != nil {
			return err
		}
		rolesToLoad := rolesToLoad(accountId, roles)
		for _, role := range rolesToLoad {
			credentials, err := ssoClient.GetRoleCredentials(accountId, role)
			if err != nil {
				return err
			}
			consoleUrl, err := consoleSignInUrl(
				*credentials,
				cfg.GetValue(config.StartUrl).(string),
				cfg.GetValue(config.Destination).(string))

			accountUrlDetails = append(accountUrlDetails, accountUrlDetail{
				consoleUrl:  consoleUrl,
				roleName:    role,
				accountInfo: accountMap[accountId],
			})
		}
	}

	if len(accountUrlDetails) == 0 {
		log.Info("No roles selected")
		return nil
	}

	for _, accountUrlDetail := range accountUrlDetails {
		log.Info("Console Login url: " + accountUrlDetail.consoleUrl)

		noOpen := cfg.GetValue(config.NoOpen).(bool)
		if !noOpen {
			useBrowserContainer := cfg.GetValue(config.UseBrowserContainer).(bool)

			if useBrowserContainer {
				accountUrlDetail.consoleUrl = containerUrl(
					accountUrlDetail.consoleUrl,
					*accountUrlDetail.accountInfo.EmailAddress,
					accountUrlDetail.roleName)
				err = open.StartWith(accountUrlDetail.consoleUrl, "firefox")
			} else {
				err = open.Start(accountUrlDetail.consoleUrl)
			}
			if err != nil {
				log.Warn("Error opening browser")
				log.Debug(err)
			}
		}
	}
	return nil
}

func containerUrl(consoleUrl string, accountEmail string, roleName string) string {
	possibleColors := []string{
		"blue",
		"turquoise",
		"green",
		"yellow",
		"orange",
		"red",
		"pink",
		"purple"}
	containerName := url.QueryEscape(accountEmail + " " + roleName)

	h := adler32.New()
	h.Write([]byte(containerName))
	hashNum := int(h.Sum32())

	color := possibleColors[hashNum%len(possibleColors)]

	return "ext+container:name=" + containerName + "&color=" + color + "&url=" + url.QueryEscape(consoleUrl)
}

func consoleSignInUrl(roleCredentials types.RoleCredentials, startUrl string, destination string) (string, error) {
	return awsconsole.GetConsoleSignInUrl(awsconsole.AwsCredentials{
		AccessKeyId:     *roleCredentials.AccessKeyId,
		Expiration:      time.Unix(roleCredentials.Expiration, 0),
		SecretAccessKey: *roleCredentials.SecretAccessKey,
		SessionToken:    *roleCredentials.SessionToken,
	}, startUrl, destination)
}

func saveProfileCredentials(accountId string, roleName string, credentials types.RoleCredentials) {

}

func rolesToLoad(accountId string, roles []types.RoleInfo) []string {
	// TODO look at profile, and role config
	if len(roles) == 0 {
		log.Warn("No roles available for account: " + accountId)
		return []string{}
	}

	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, *role.RoleName)
	}

	var selected []string
	err := survey.AskOne(&survey.MultiSelect{
		Message: "Select role(s) for " + accountId,
		Options: roleNames,
	}, &selected)

	if err != nil {
		log.Error(err)
	}
	return selected
}

func accountsToLoad(listedAccounts []types.AccountInfo) []string {

	if len(listedAccounts) == 0 {
		log.Error("No accounts available via SSO")
		return nil
	}

	if len(listedAccounts) == 1 {
		log.Debug("Only one account available via SSO")
		return []string{*listedAccounts[0].AccountId}
	}

	var listedAccountIds []string
	for _, acc := range listedAccounts {
		listedAccountIds = append(listedAccountIds, *acc.AccountId)
	}
	desiredAccountsToLoad := desiredAccountsToLoad()

	var accountsToLoad []string
	if len(desiredAccountsToLoad) > 0 {
		listedAccountIdSet := stringset.New(listedAccountIds)
		for _, desiredAccount := range desiredAccountsToLoad {
			if listedAccountIdSet.Contains(desiredAccount) {
				accountsToLoad = append(accountsToLoad, desiredAccount)
			} else {
				log.Warn("Desired account not available in SSO account listing. Account ID: " + desiredAccount)
			}
		}
		log.Info("Loading desired accounts: " + strings.Join(accountsToLoad, ","))
	} else {
		if cfg.InteractiveAllowed() {

			var options []string
			optionToIdx := make(map[string]int)
			for i, account := range listedAccounts {
				option := *account.AccountId + ", " + *account.AccountName + ", (" + *account.EmailAddress + ")"
				options = append(options, option)
				optionToIdx[option] = i
			}

			var selected []string
			err := survey.AskOne(&survey.MultiSelect{
				Message: "Select account(s)",
				Options: options,
			}, &selected)

			for _, selection := range selected {
				accountsToLoad = append(accountsToLoad, *listedAccounts[optionToIdx[selection]].AccountId)
			}

			if err != nil {
				log.Error(err)
			}
		}
	}

	return accountsToLoad
}

func desiredAccountsToLoad() []string {
	var accountIds []string
	configAccounts := cfg.GetValue(config.Accounts).([]string)
	if configAccounts != nil {
		accountIds = append(accountIds, configAccounts...)
	}
	configProfiles := cfg.GetValue(config.Profiles).([]string)
	if configProfiles != nil {
		for _, profileName := range configProfiles {
			profile, err := awsconfig.LoadSharedConfigProfile(context.TODO(), profileName)
			if err != nil {
				log.Warn("Error loading profile: " + profileName)
				log.Debug(err)
			}
			if profile.SSOAccountID != "" {
				accountIds = append(accountIds, profile.SSOAccountID)
			} else {
				log.Warn("Ignoring profile with no sso_account_id: " + profileName)
			}
		}
	}
	return accountIds
}

type MessageOnlyFormatter struct{}

func (f *MessageOnlyFormatter) Format(entry *log.Entry) ([]byte, error) {
	return []byte(entry.Message + "\n"), nil
}

var _ log.Formatter = &MessageOnlyFormatter{}

func configureLogging(c cli.Context) {
	log.SetOutput(os.Stdout)

	messageOnlyLogging := true
	if c.Bool("silent") {
		log.SetLevel(log.PanicLevel)
	}

	if c.Bool("quiet") {
		log.SetLevel(log.WarnLevel)
	}

	if c.Bool("verbose") {
		messageOnlyLogging = false
		log.SetLevel(log.DebugLevel)
	}

	if c.Bool("trace") {
		messageOnlyLogging = false
		log.SetLevel(log.TraceLevel)
		awsLogging = aws.LogRequestWithBody | aws.LogResponseWithBody
	}
	if messageOnlyLogging {
		log.SetFormatter(&MessageOnlyFormatter{})
	}
}

func acquireSsoAuthentication() (*ssooidc.BotoAccessTokenCache, error, bool) {
	ssoOidcClient := ssooidc.NewClient(cfg.AwsConfig())
	startUrl := cfg.GetValue(config.StartUrl).(string)
	if startUrl == "" {
		return nil, errors.New("start URL required and not specified, or configured"), false
	}
	startAuthorisation, err := ssoOidcClient.StartDeviceAuthorisation(startUrl)
	if err != nil {
		return nil, err, false
	}
	ignoreCache := cfg.GetValue(config.IgnoreCachedAccessToken).(bool)
	var accessToken *ssooidc.BotoAccessTokenCache
	if !ignoreCache {
		accessToken = ssooidc.ReadNonExpiredAccessTokenCache(startUrl)
		if accessToken != nil {
			return accessToken, nil, true
		}
	}

	noOpen := cfg.GetValue(config.NoOpen).(bool)
	if !noOpen {
		log.Println("Attempting to automatically open the SSO authorization page in your default browser.")
		err := open.Start(*startAuthorisation.VerificationUriComplete)
		if err != nil {
			log.Warn("Error opening browser")
			log.Debug(err)
		}
	}
	log.Println("If the browser does not open or you wish to use a different device to authorize this request, open the following URL:")
	log.Println("Verification URL: " + *startAuthorisation.VerificationUriComplete)
	log.Println("If prompted, enter the following code: " + *startAuthorisation.UserCode)

	authorisation, err := ssoOidcClient.PollingDeviceAuthorisation(
		time.Duration(startAuthorisation.Interval)*time.Second,
		*startAuthorisation.DeviceCode)
	if err != nil {
		return nil, err, false
	}
	accessToken, err = ssoOidcClient.BuildAndSaveBotoAccessToken(startUrl, authorisation)
	if err != nil {
		return nil, err, false
	}

	return accessToken, nil, false
}

func ssoRegion(awsCfg aws.Config) *string {
	var sharedConfig *awsconfig.SharedConfig
	for _, awscfg := range awsCfg.ConfigSources {
		switch c := awscfg.(type) {
		case awsconfig.SharedConfig:
			sharedConfig = &c
		case *awsconfig.SharedConfig:
			sharedConfig = c
		}
	}
	if sharedConfig != nil {
		return &sharedConfig.SSORegion
	}
	return nil
}

func ssoClientAwsConfig() (*aws.Config, error) {
	awscfg, err := awsconfig.LoadDefaultConfig(context.TODO(), awsconfig.WithClientLogMode(awsLogging))
	if err != nil {
		return nil, err
	}
	ssoRegion := ssoRegion(awscfg)
	if ssoRegion != nil && *ssoRegion != "" {
		awscfg.Region = *ssoRegion
	}
	return &awscfg, nil
}

func ssoStartUrlCandidates() []string {
	configIni, err := loadAwsConfigIni()
	var ssoStartUrlCandidates []string
	if err == nil {
		for _, section := range configIni.Sections() {
			if section.HasKey("sso_start_url") {
				key, err := section.GetKey("sso_start_url")
				if err != nil {
					continue
				}
				ssoStartUrlCandidates = append(ssoStartUrlCandidates, key.Value())
			}
		}
	}
	return ssoStartUrlCandidates
}

func loadAwsConfigIni() (*ini.File, error) {
	var iniFilePath = awsconfig.DefaultSharedConfigFilename()
	envConfig, err := awsconfig.NewEnvConfig()
	if err == nil && len(envConfig.SharedConfigFile) > 0 {
		iniFilePath = envConfig.SharedConfigFile
	}
	return ini.Load(iniFilePath)
}
