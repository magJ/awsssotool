package main

import (
	"awsssotool/internal/awsconsole"
	"awsssotool/internal/config"
	"awsssotool/internal/sso"
	"awsssotool/internal/ssooidc"
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
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var awsLogging aws.ClientLogMode
var cfg config.Context
var knownAwsRegions = []string{
	"us-east-2",
	"us-east-1",
	"us-west-1",
	"us-west-2",
	"af-south-1",
	"ap-east-1",
	"ap-south-1",
	"ap-northeast-3",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"ca-central-1",
	"cn-north-1",
	"cn-northwest-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-south-1",
	"eu-west-3",
	"eu-north-1",
	"me-south-1",
	"sa-east-1",
}

func main() {
	var app = &cli.App{
		Name:        "awsssotool",
		Usage:       "The missing AWS SSO cli tool",
		Description: "Various utilities to make using AWS SSO easier",
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
				Usage: "Acquires and caches AWS SSO device authorisation, opens a browser to SSO CLI auth page if necessary.",
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
						Name:  config.SsoRegion.Name(),
						Usage: "Region to use with SSO apis",
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: config.StartUrl.Name(),
						Usage: "URL to AWS SSO start page.\n" +
							"If not specified, we will attempt to discover it from AWS config.",
					},
					&cli.StringFlag{
						Name:  config.SsoRegion.Name(),
						Usage: "Region to use with SSO apis",
					},
				},
			},
			{
				Name:  "console",
				Usage: "Opens a browser session to the AWS console, using a selected account/role",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: config.StartUrl.Name(),
						Usage: "URL to AWS SSO start page.\n" +
							"If not specified, we will attempt to discover it from AWS config.",
					},
					&cli.StringFlag{
						Name:  config.SsoRegion.Name(),
						Usage: "Region to use with SSO apis",
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
	candidates := ssoStartUrlCandidates()
	defaultStartUrl := ""
	if len(candidates) > 0 {
		defaultStartUrl = candidates[0]
	}

	var startUrl string
	err := survey.AskOne(&survey.Input{
		Message: "SSO Start URL",
		Default: defaultStartUrl,
		Help:    "The URL to your AWS SSO start page. eg https://example.awsapps.com/start",
	}, &startUrl)
	if err != nil {
		return err
	}
	var ssoRegion string
	err = survey.AskOne(&survey.Input{
		Message: "SSO Region",
		Help:    "The region to use when communicating with the AWS SSO API",
		Suggest: startsWithCompleter(knownAwsRegions),
	}, &ssoRegion)
	if err != nil {
		return err
	}

	var useBrowserContainer bool
	err = survey.AskOne(&survey.Confirm{
		Message: "Use firefox container support?",
		Default: false,
		Help:    "Requires the firefox containers plugin, and the `open-url-in-container` plugin (https://github.com/honsiorovskyi/open-url-in-container)",
	}, &useBrowserContainer)

	err = config.SaveConfig(config.ToolPersistentConfig{
		StartUrl:            &startUrl,
		SsoRegion:           &ssoRegion,
		UseContainerSupport: &useBrowserContainer,
	})
	if err != nil {
		return err
	}
	log.Info("Config saved")
	return nil
}

func startsWithCompleter(completions []string) func(toComplete string) []string {
	return func(toComplete string) []string {
		var suggestions []string
		for _, completion := range completions {
			if strings.HasPrefix(completion, toComplete) {
				suggestions = append(suggestions, completion)
			}
		}
		return suggestions
	}
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

	var profilesLoaded []string
	var accountsToLoad = accountsToLoad(listedAccounts)
	for _, accountId := range accountsToLoad {
		roles, err := ssoClient.ListAccountRoles(accountId)
		if err != nil {
			return err
		}
		rolesToLoad := rolesToLoad(accountId, roles)
		for _, role := range rolesToLoad {
			credentials, err := ssoClient.GetRoleCredentials(accountId, role.roleName)
			if err != nil {
				return err
			}
			profileName, err := saveProfileCredentials(accountId, role, *credentials)
			if err != nil {
				log.Error("Error saving credentials account: " + accountId + ", role: " + role.roleName)
				return err
			}
			profilesLoaded = append(profilesLoaded, profileName)
		}
	}
	log.Info("Credentials synced for profiles: " + strings.Join(profilesLoaded, ", "))
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
			credentials, err := ssoClient.GetRoleCredentials(accountId, role.roleName)
			if err != nil {
				return err
			}
			consoleUrl, err := consoleSignInUrl(
				*credentials,
				cfg.GetValue(config.StartUrl).(string),
				cfg.GetValue(config.Destination).(string))

			accountUrlDetails = append(accountUrlDetails, accountUrlDetail{
				consoleUrl:  consoleUrl,
				roleName:    role.roleName,
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

				if runtime.GOOS == "darwin" {
					// macOs open(1) doesnt otherwise like the extension prefixed url
					err = exec.Command("open", "-a", "firefox", "-n", "--args", accountUrlDetail.consoleUrl).Start()
				} else {
					err = open.StartWith(accountUrlDetail.consoleUrl, "firefox")
				}
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
		Expiration:      time.Unix(0, roleCredentials.Expiration*int64(time.Millisecond)).UTC(),
		SecretAccessKey: *roleCredentials.SecretAccessKey,
		SessionToken:    *roleCredentials.SessionToken,
	}, startUrl, destination)
}

func saveProfileCredentials(accountId string, roleDetail roleDetail, credentials types.RoleCredentials) (string, error) {

	iniPath := awsconfig.DefaultSharedCredentialsFilename()
	err := touch(iniPath)
	if err != nil {
		return "", err
	}
	iniData, err := ini.Load(iniPath)
	if err != nil {
		return "", err
	}
	var profileName string
	if roleDetail.profileName != "" {
		profileName = roleDetail.profileName
	} else {
		profileName = roleDetail.roleName + "-" + accountId
	}
	section := iniData.Section(profileName)
	section, err = iniData.NewSection(profileName)
	if err != nil {
		return "", err
	}
	_, err = section.NewKey("region", cfg.AwsConfig().Region)
	if err != nil {
		return "", err
	}
	err = config.UpsertKey(section, "aws_access_key_id", *credentials.AccessKeyId)
	if err != nil {
		return "", err
	}
	err = config.UpsertKey(section, "aws_secret_access_key", *credentials.SecretAccessKey)
	if err != nil {
		return "", err
	}
	err = config.UpsertKey(section, "aws_session_token", *credentials.SessionToken)
	if err != nil {
		return "", err
	}
	err = config.UpsertKey(section, "aws_session_expiration", time.Unix(0, credentials.Expiration*int64(time.Millisecond)).UTC().Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	err = iniData.SaveTo(iniPath)
	if err != nil {
		return "", err
	}

	return profileName, nil
}

func touch(filePath string) error {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func rolesToLoad(accountId string, roles []types.RoleInfo) []roleDetail {
	if len(roles) == 0 {
		log.Warn("No roles available for account: " + accountId)
		return []roleDetail{}
	}

	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, *role.RoleName)
	}
	listedRoleNameSet := stringset.New(roleNames)
	desiredRoles := desiredRolesToLoad(accountId)
	if len(desiredRoles) > 0 {
		var matchingRoles []roleDetail
		for _, role := range desiredRoles {
			if listedRoleNameSet.Contains(role.roleName) {
				matchingRoles = append(matchingRoles, role)
			} else {
				log.Warn("Desired role not available in SSO role listing, Role name: " + role.roleName)
			}
		}
		var matchingRoleNames []string
		for _, role := range matchingRoles {
			matchingRoleNames = append(matchingRoleNames, role.roleName)
		}
		log.Info("Loading desired roles: " + strings.Join(matchingRoleNames, ","))
		return matchingRoles
	}

	if cfg.InteractiveAllowed() {
		var selected []string
		err := survey.AskOne(&survey.MultiSelect{
			Message: "Select role(s) for " + accountId,
			Options: roleNames,
		}, &selected)

		if err != nil {
			log.Error(err)
		}
		var selectedDetails []roleDetail
		for _, selection := range selected {
			selectedDetails = append(selectedDetails, roleDetail{
				roleName:    selection,
				profileName: "",
			})
		}
		return selectedDetails
	}
	return []roleDetail{}
}

type roleDetail struct {
	roleName    string
	profileName string
}

func desiredRolesToLoad(accountId string) []roleDetail {
	var desiredRoles []roleDetail
	configRoles := cfg.GetValue(config.Roles).([]string)
	if configRoles != nil {
		for _, cr := range configRoles {
			desiredRoles = append(desiredRoles, roleDetail{
				roleName:    cr,
				profileName: "",
			})
		}
	}
	profiles := getNominatedSsoProfiles()
	for _, profile := range profiles {
		if profile.SSOAccountID == accountId && profile.SSORoleName != "" {
			desiredRoles = append(desiredRoles, roleDetail{
				roleName:    profile.SSORoleName,
				profileName: profile.Profile,
			})
		}
	}
	return desiredRoles
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
	profiles := getNominatedSsoProfiles()
	for _, profile := range profiles {
		accountIds = append(accountIds, profile.SSOAccountID)
	}
	return unique(accountIds)
}

func unique(stringSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func getNominatedSsoProfiles() []awsconfig.SharedConfig {
	var profiles []awsconfig.SharedConfig
	configProfiles := cfg.GetValue(config.Profiles).([]string)
	if configProfiles != nil {
		for _, profileName := range configProfiles {
			profile, err := awsconfig.LoadSharedConfigProfile(context.TODO(), profileName)
			if err != nil {
				log.Warn("Error loading profile: " + profileName)
				log.Debug(err)
			}
			if profile.SSOAccountID != "" {
				profiles = append(profiles, profile)
			} else {
				log.Warn("Ignoring profile with no sso_account_id: " + profileName)
			}
		}
	}
	return profiles
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
	configIni, err := ini.Load(awsConfigIniPath())
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

func awsConfigIniPath() string {
	var iniFilePath = awsconfig.DefaultSharedConfigFilename()
	envConfig, err := awsconfig.NewEnvConfig()
	if err == nil && len(envConfig.SharedConfigFile) > 0 {
		iniFilePath = envConfig.SharedConfigFile
	}
	return iniFilePath
}
