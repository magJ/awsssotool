package sso

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
)

type Client struct {
	ssoClient   sso.Client
	accessToken string
}

func NewClient(cfg aws.Config, accessToken string) Client {
	return Client{
		ssoClient:   *sso.NewFromConfig(cfg),
		accessToken: accessToken,
	}
}

func (c *Client) ListAccounts() ([]types.AccountInfo, error) {
	var accounts []types.AccountInfo
	paginator := sso.NewListAccountsPaginator(&c.ssoClient, &sso.ListAccountsInput{
		AccessToken: aws.String(c.accessToken),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, page.AccountList...)
	}
	return accounts, nil
}

func (c *Client) ListAccountRoles(accountId string) ([]types.RoleInfo, error) {
	var accounts []types.RoleInfo
	paginator := sso.NewListAccountRolesPaginator(&c.ssoClient, &sso.ListAccountRolesInput{
		AccessToken: aws.String(c.accessToken),
		AccountId:   aws.String(accountId),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, page.RoleList...)
	}
	return accounts, nil
}

func (c *Client) GetRoleCredentials(accountId string, roleName string) (*types.RoleCredentials, error) {
	credentials, err := c.ssoClient.GetRoleCredentials(context.TODO(), &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(c.accessToken),
		AccountId:   aws.String(accountId),
		RoleName:    aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}
	return credentials.RoleCredentials, err
}
