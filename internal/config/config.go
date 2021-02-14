package config

import (
	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v2"
	"os"
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
)

type configItem struct {
	name            string
	fromCli         func(cli *cli.Context) interface{}
	fromAwsConfig   func(awsconfig aws.Config) interface{}
	fromInteractive func() interface{}
}

type Context struct {
	rootCliContext    *cli.Context
	commandCliContext *cli.Context
	aws               aws.Config
}

var (
	StartUrl = configItem{
		name:    startUrl,
		fromCli: stringCliFunc(startUrl),
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
			}, startUrl)
			if err != nil {
				return nil
			}
			return startUrl
		},
	}
	NoInteractive = configItem{
		name:    noInteractive,
		fromCli: boolCliFunc(noInteractive),
	}
	NoOpen = configItem{
		name:    noOpen,
		fromCli: boolCliFunc(noOpen),
	}
	UseBrowserContainer = configItem{
		name:    useBrowserContainer,
		fromCli: boolCliFunc(useBrowserContainer),
	}
	IgnoreCachedAccessToken = configItem{
		name:    ignoreCachedAccessToken,
		fromCli: boolCliFunc(ignoreCachedAccessToken),
	}
	Accounts = configItem{
		name:    accounts,
		fromCli: stringSliceCliFunc(accounts),
	}
	Roles = configItem{
		name:    roles,
		fromCli: stringSliceCliFunc(roles),
	}
	Profiles = configItem{
		name:    profiles,
		fromCli: stringSliceCliFunc(profiles),
	}
	Destination = configItem{
		name:    destination,
		fromCli: stringCliFunc(destination),
	}
)

func stringSliceCliFunc(name string) func(cli *cli.Context) interface{} {
	return func(cli *cli.Context) interface{} {
		return cli.StringSlice(name)
	}
}

func boolCliFunc(name string) func(cli *cli.Context) interface{} {
	return func(cli *cli.Context) interface{} {
		return cli.Bool(name)
	}
}

func stringCliFunc(name string) func(cli *cli.Context) interface{} {
	return func(cli *cli.Context) interface{} {
		return cli.String(name)
	}
}

func NewConfigContext(cli *cli.Context, aws aws.Config) Context {
	return Context{
		rootCliContext: cli,
		aws:            aws,
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

	if ci.fromAwsConfig != nil {
		fromAwsConfig := ci.fromAwsConfig(context.aws)
		if fromAwsConfig != nil {
			return fromAwsConfig
		}
	}

	if context.InteractiveAllowed() && ci.fromInteractive != nil {
		return ci.fromInteractive()
	}
	return nil
}

func (cc *Context) SetCommandContext(commandContext *cli.Context) {
	cc.commandCliContext = commandContext
}

func (cc Context) InteractiveAllowed() bool {
	noInteractive := cc.GetValue(NoInteractive).(bool)
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
