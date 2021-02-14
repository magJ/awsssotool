package config

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/mattn/go-isatty"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/ini.v1"
	"os"
	"path/filepath"
	"strconv"
)

const (
	startUrl                = "start-url"
	noInteractive           = "no-interactive"
	noOpen                  = "no-open"
	useBrowserContainer     = "use-browser-container"
	ignoreCachedAccessToken = "ignore-cached-access-token"
	accounts                = "accounts"
	roles                   = "roles"
	profiles                = "profiles"
	destination             = "destination"
	ssoRegion               = "sso-region"
)

type ToolPersistentConfig struct {
	StartUrl            *string
	SsoRegion           *string
	UseContainerSupport *bool
}

func configFilePath() (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	config.DefaultSharedCredentialsFilename()
	return filepath.Join(dir, ".aws", "magj-ssotool"), nil
}

func SaveConfig(conf ToolPersistentConfig) error {
	iniFile, err := ini.Load([]byte{})
	if err != nil {
		return err
	}
	section, err := upsertSection(iniFile, "default")
	if err != nil {
		return err
	}
	err = UpsertKey(section, "sso_region", *conf.SsoRegion)
	if err != nil {
		return err
	}
	err = UpsertKey(section, "sso_start_url", *conf.StartUrl)
	if err != nil {
		return err
	}
	err = UpsertKey(section, useBrowserContainer, strconv.FormatBool(*conf.UseContainerSupport))
	if err != nil {
		return err
	}
	path, err := configFilePath()
	if err != nil {
		return err
	}
	return iniFile.SaveTo(path)
}

func LoadConfig() (*ToolPersistentConfig, error) {
	path, err := configFilePath()
	if err != nil {
		return nil, err
	}
	iniFile, err := ini.Load(path)
	if err != nil {
		return nil, err
	}
	section, err := iniFile.GetSection("default")
	if err != nil {
		return nil, err
	}

	useBrowserContainer, _ := strconv.ParseBool(section.Key(useBrowserContainer).Value())
	ssoStartUrl := section.Key("sso_start_url").Value()
	ssoRegion := section.Key("sso_region").Value()
	return &ToolPersistentConfig{
		StartUrl:            &ssoStartUrl,
		SsoRegion:           &ssoRegion,
		UseContainerSupport: &useBrowserContainer,
	}, nil
}

func UpsertKey(section *ini.Section, key string, value string) error {
	hasKey := section.HasKey(key)
	if hasKey {
		section.Key(key).SetValue(value)
	} else {
		_, err := section.NewKey(key, value)
		return err
	}
	return nil
}

func upsertSection(file *ini.File, sectionName string) (*ini.Section, error) {
	section := file.Section(sectionName)
	if section == nil {
		return file.NewSection(sectionName)
	}
	return section, nil
}

type configItem struct {
	name            string
	fromCli         func(cli *cli.Context) interface{}
	fromAwsConfig   func(awsconfig aws.Config) interface{}
	fromInteractive func() interface{}
	fromFileConfig  func(fileConfig ToolPersistentConfig) interface{}
	defaultEmpty    interface{}
}

type Context struct {
	rootCliContext    *cli.Context
	commandCliContext *cli.Context
	fileConfig        *ToolPersistentConfig
	aws               aws.Config
}

var (
	StartUrl = configItem{
		name:         startUrl,
		fromCli:      stringCliFunc(startUrl),
		defaultEmpty: "",
		fromAwsConfig: func(awsconfig aws.Config) interface{} {
			c := sharedConfig(awsconfig)
			if c != nil {
				return c.SSOStartURL
			}
			return nil
		},
		fromInteractive: func() interface{} {
			var startUrl *string
			err := survey.AskOne(&survey.Input{
				Message: "SSO Start Url",
			}, &startUrl)
			if err != nil {
				return nil
			}
			if startUrl == nil {
				return nil
			}
			return *startUrl
		},
		fromFileConfig: func(fileConfig ToolPersistentConfig) interface{} {
			if fileConfig.StartUrl == nil {
				return nil
			}
			return *fileConfig.StartUrl
		},
	}
	NoInteractive = configItem{
		name:         noInteractive,
		fromCli:      boolCliFunc(noInteractive),
		defaultEmpty: false,
	}
	NoOpen = configItem{
		name:         noOpen,
		fromCli:      boolCliFunc(noOpen),
		defaultEmpty: false,
	}
	UseBrowserContainer = configItem{
		name:         useBrowserContainer,
		fromCli:      boolCliFunc(useBrowserContainer),
		defaultEmpty: false,
		fromFileConfig: func(fileConfig ToolPersistentConfig) interface{} {
			if fileConfig.UseContainerSupport == nil {
				return nil
			}
			return *fileConfig.UseContainerSupport
		},
	}
	IgnoreCachedAccessToken = configItem{
		name:         ignoreCachedAccessToken,
		fromCli:      boolCliFunc(ignoreCachedAccessToken),
		defaultEmpty: false,
	}
	Accounts = configItem{
		name:         accounts,
		fromCli:      stringSliceCliFunc(accounts),
		defaultEmpty: []string{},
	}
	Roles = configItem{
		name:         roles,
		fromCli:      stringSliceCliFunc(roles),
		defaultEmpty: []string{},
	}
	Profiles = configItem{
		name:         profiles,
		fromCli:      stringSliceCliFunc(profiles),
		defaultEmpty: []string{},
	}
	Destination = configItem{
		name:         destination,
		fromCli:      stringCliFunc(destination),
		defaultEmpty: "",
	}
	SsoRegion = configItem{
		name:         ssoRegion,
		fromCli:      stringCliFunc(ssoRegion),
		defaultEmpty: "",
		fromAwsConfig: func(awsconfig aws.Config) interface{} {
			c := sharedConfig(awsconfig)
			if c != nil {
				return c.SSORegion
			}
			return awsconfig.Region
		},
		fromFileConfig: func(fileConfig ToolPersistentConfig) interface{} {
			return fileConfig.SsoRegion
		},
	}
)

func stringSliceCliFunc(name string) func(cli *cli.Context) interface{} {
	return func(cli *cli.Context) interface{} {
		if !cli.IsSet(name) {
			return nil
		}
		slice := cli.StringSlice(name)
		return &slice
	}
}

func boolCliFunc(name string) func(cli *cli.Context) interface{} {
	return func(cli *cli.Context) interface{} {
		if !cli.IsSet(name) {
			return nil
		}
		return cli.Bool(name)
	}
}

func stringCliFunc(name string) func(cli *cli.Context) interface{} {
	return func(cli *cli.Context) interface{} {
		if !cli.IsSet(name) {
			return nil
		}
		return cli.String(name)
	}
}

func NewConfigContext(cli *cli.Context, aws aws.Config) Context {
	loadConfig, err := LoadConfig()
	if err != nil {
		log.Debug("Could not load config", err)
	}
	return Context{
		rootCliContext: cli,
		aws:            aws,
		fileConfig:     loadConfig,
	}
}

func (ci configItem) Name() string {
	return ci.name
}

func (ci configItem) getValue(context *Context) interface{} {
	if ci.fromCli != nil {
		fromCli := ci.fromCli(context.commandCliContext)
		if fromCli != nil {
			return fromCli
		}
		fromCli = ci.fromCli(context.rootCliContext)
		if fromCli != nil {
			return fromCli
		}
	}

	if ci.fromFileConfig != nil && context.fileConfig != nil {
		fromFileConfig := ci.fromFileConfig(*context.fileConfig)
		if fromFileConfig != nil {
			return fromFileConfig
		}
	}

	if ci.fromAwsConfig != nil {
		fromAwsConfig := ci.fromAwsConfig(context.aws)
		if fromAwsConfig != nil {
			return fromAwsConfig
		}
	}

	if context.InteractiveAllowed() && ci.fromInteractive != nil {
		return ci.fromInteractive()
	}
	return ci.defaultEmpty
}

func (cc *Context) SetCommandContext(commandContext *cli.Context) {
	cc.commandCliContext = commandContext
}

func (cc Context) InteractiveAllowed() bool {
	noInteractive := cc.commandCliContext.Bool(noInteractive)
	isTty := isatty.IsTerminal(os.Stdout.Fd())
	return isTty && !noInteractive
}

func (cc Context) GetValue(ci configItem) interface{} {
	return ci.getValue(&cc)
}

func (cc Context) AwsConfig() aws.Config {
	return cc.aws
}

func sharedConfig(awsconfig aws.Config) *config.SharedConfig {
	var sharedConfig *config.SharedConfig
	for _, cfg := range awsconfig.ConfigSources {
		switch c := cfg.(type) {
		case config.SharedConfig:
			sharedConfig = &c
		case *config.SharedConfig:
			sharedConfig = c
		}
	}
	if sharedConfig != nil {
		return sharedConfig
	}
	return nil
}
