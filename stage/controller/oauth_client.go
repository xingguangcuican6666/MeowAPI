/*
Copyright (C) 2023-2026 xingguangcuican6666

This file is part of new-api, which is licensed under the GNU Affero General
Public License v3.0. Original project: https://github.com/QuantumNous/new-api

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"errors"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/oauthserver"

	"github.com/gin-gonic/gin"
)

// This file implements the dashboard-side management surface for new-api's OAuth
// authorization server: admin (RootAuth) CRUD over registered client
// applications, and the signed-in user's view of which applications they have
// authorized. The public OAuth wire endpoints live in oauth_server.go.

// oauthClientRequest is the admin create/update payload for a client app.
type oauthClientRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Logo         string   `json:"logo"`
	Homepage     string   `json:"homepage"`
	RedirectUris []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	IsPublic     bool     `json:"is_public"`
	// Trusted is honored only for an admin/root caller (see applyOAuthClientRequest);
	// a common user's value is ignored so the sensitive-scope gate cannot be bypassed.
	Trusted bool `json:"trusted"`
	Status  int  `json:"status"`
}

// oauthClientResponse is the client shape returned to the dashboard, decoding
// the stored JSON/space-delimited fields into arrays. The secret hash is never
// included (OAuthClient hides it via json:"-").
type oauthClientResponse struct {
	Id           int      `json:"id"`
	ClientId     string   `json:"client_id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Logo         string   `json:"logo"`
	Homepage     string   `json:"homepage"`
	RedirectUris []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	IsPublic     bool     `json:"is_public"`
	Trusted      bool     `json:"trusted"`
	Status       int      `json:"status"`
	OwnerUserId  int      `json:"owner_user_id"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
}

func newOAuthClientResponse(client *model.OAuthClient) oauthClientResponse {
	return oauthClientResponse{
		Id:           client.Id,
		ClientId:     client.ClientId,
		Name:         client.Name,
		Description:  client.Description,
		Logo:         client.Logo,
		Homepage:     client.Homepage,
		RedirectUris: client.GetRedirectUris(),
		Scopes:       client.GetScopes(),
		IsPublic:     client.IsPublic,
		Trusted:      client.Trusted,
		Status:       client.Status,
		OwnerUserId:  client.OwnerUserId,
		CreatedAt:    client.CreatedAt,
		UpdatedAt:    client.UpdatedAt,
	}
}

// applyOAuthClientRequest copies request fields onto a client, rejecting scopes
// outside the server catalog. Redirect-URI shape and non-empty scopes/URIs are
// enforced by OAuthClient.validate() on Insert/Update.
//
// Two access-control invariants are enforced here server-side (never trusting
// the client payload, OWASP ASVS V4):
//   - Trusted is an administrator-only attribute; a non-admin caller's value is
//     ignored, leaving the stored value unchanged (false for a new client).
//   - A sensitive scope (wallet.topup / apikeys.manage) may be held only while
//     the client is Trusted, re-checked at write time (defense in depth), not
//     only when a token is later issued.
func applyOAuthClientRequest(c *gin.Context, client *model.OAuthClient, req *oauthClientRequest) error {
	scopes := oauthserver.ParseScopes(strings.Join(req.Scopes, " "))
	for _, scope := range scopes {
		if !oauthserver.IsSupportedScope(scope) {
			return errors.New("unknown scope: " + scope)
		}
	}
	if callerIsOAuthAdmin(c) {
		client.Trusted = req.Trusted
	}
	if oauthserver.ContainsSensitiveScope(scopes) && !client.Trusted {
		return errors.New("敏感 scope 需要管理员先将该应用标记为可信（trusted）")
	}
	encodedUris, err := common.Marshal(req.RedirectUris)
	if err != nil {
		return err
	}
	client.Name = strings.TrimSpace(req.Name)
	client.Description = req.Description
	client.Logo = req.Logo
	client.Homepage = req.Homepage
	client.RedirectUris = string(encodedUris)
	client.Scopes = oauthserver.JoinScopes(scopes)
	client.IsPublic = req.IsPublic
	if req.Status == model.OAuthClientStatusDisabled {
		client.Status = model.OAuthClientStatusDisabled
	} else {
		client.Status = model.OAuthClientStatusEnabled
	}
	return nil
}

// callerIsOAuthAdmin reports whether the request is made by an admin or root
// user, who may manage every OAuth application regardless of ownership.
func callerIsOAuthAdmin(c *gin.Context) bool {
	return c.GetInt("role") >= common.RoleAdminUser
}

// loadManageableOAuthClient loads a client for a management action and enforces
// ownership for non-admin callers. A non-owner referencing someone else's client
// gets ErrOAuthClientNotFound rather than a distinct 403, so client existence is
// never leaked to unauthorized users (IDOR protection). Admins and root manage
// any client.
func loadManageableOAuthClient(c *gin.Context, id int) (*model.OAuthClient, error) {
	client, err := model.GetOAuthClientById(id)
	if err != nil {
		return nil, err
	}
	if !callerIsOAuthAdmin(c) && client.OwnerUserId != c.GetInt("id") {
		return nil, model.ErrOAuthClientNotFound
	}
	return client, nil
}

// ListOAuthClients backs GET /api/oauth-server/clients (UserAuth). Admins see
// every registered client; a common user sees only the clients they own.
func ListOAuthClients(c *gin.Context) {
	var clients []*model.OAuthClient
	var err error
	if callerIsOAuthAdmin(c) {
		clients, err = model.GetAllOAuthClients()
	} else {
		clients, err = model.GetOAuthClientsByOwner(c.GetInt("id"))
	}
	if err != nil {
		common.ApiError(c, err)
		return
	}
	out := make([]oauthClientResponse, 0, len(clients))
	for _, client := range clients {
		out = append(out, newOAuthClientResponse(client))
	}
	common.ApiSuccess(c, out)
}

// GetOAuthClient backs GET /api/oauth-server/clients/:id (UserAuth); non-admins
// may only read a client they own.
func GetOAuthClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiErrorMsg(c, "invalid client id")
		return
	}
	client, err := loadManageableOAuthClient(c, id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, newOAuthClientResponse(client))
}

// CreateOAuthClient backs POST /api/oauth-server/clients (UserAuth). It mints a
// client_id and, for confidential clients, a client secret returned exactly once
// in plaintext (only its hash is stored). Admins and root may always create
// applications; a common user needs the admin-granted CanCreateOAuthApp flag.
func CreateOAuthClient(c *gin.Context) {
	if !callerIsOAuthAdmin(c) {
		allowed, err := model.IsUserAllowedToCreateOAuthApp(c.GetInt("id"))
		if err != nil {
			common.ApiError(c, err)
			return
		}
		if !allowed {
			common.ApiErrorMsg(c, "您没有创建 OAuth 应用的权限")
			return
		}
	}
	var req oauthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiErrorMsg(c, "invalid request body")
		return
	}
	client := &model.OAuthClient{
		ClientId:    model.GenerateOAuthClientId(),
		OwnerUserId: c.GetInt("id"),
	}
	if err := applyOAuthClientRequest(c, client, &req); err != nil {
		common.ApiErrorMsg(c, err.Error())
		return
	}
	var secret string
	if !client.IsPublic {
		generated, err := model.GenerateOAuthClientSecret()
		if err != nil {
			common.ApiError(c, err)
			return
		}
		secret = generated
		client.SetSecret(secret)
	}
	if err := client.Insert(); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{
		"client": newOAuthClientResponse(client),
		"secret": secret,
	})
}

// UpdateOAuthClient backs PUT /api/oauth-server/clients/:id (UserAuth). The
// stored secret is preserved (the loaded client carries its hash); switching a
// client to public clears the secret so a stale one can never be replayed.
// Non-admins may only update a client they own.
func UpdateOAuthClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiErrorMsg(c, "invalid client id")
		return
	}
	client, err := loadManageableOAuthClient(c, id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	var req oauthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiErrorMsg(c, "invalid request body")
		return
	}
	wasPublic := client.IsPublic
	if err := applyOAuthClientRequest(c, client, &req); err != nil {
		common.ApiErrorMsg(c, err.Error())
		return
	}
	if client.IsPublic && !wasPublic {
		client.SecretHash = ""
	}
	if err := client.Update(); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, newOAuthClientResponse(client))
}

// RotateOAuthClientSecret backs POST /api/oauth-server/clients/:id/rotate-secret
// (UserAuth), issuing a fresh secret and returning it once. Existing tokens keep
// working; only future client authentication requires the new secret. Non-admins
// may only rotate a secret for a client they own.
func RotateOAuthClientSecret(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiErrorMsg(c, "invalid client id")
		return
	}
	client, err := loadManageableOAuthClient(c, id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if client.IsPublic {
		common.ApiErrorMsg(c, "public clients do not use a client secret")
		return
	}
	secret, err := model.GenerateOAuthClientSecret()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	client.SetSecret(secret)
	if err := client.Update(); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{
		"client": newOAuthClientResponse(client),
		"secret": secret,
	})
}

// DeleteOAuthClient backs DELETE /api/oauth-server/clients/:id (UserAuth),
// cascading to the client's OAuth tokens, consent grants and app-minted relay
// keys. Non-admins may only delete a client they own.
func DeleteOAuthClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiErrorMsg(c, "invalid client id")
		return
	}
	if _, err := loadManageableOAuthClient(c, id); err != nil {
		common.ApiError(c, err)
		return
	}
	if err := model.DeleteOAuthClient(id); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, nil)
}

// GetOAuthServerScopes backs GET /api/oauth-server/scopes (UserAuth), returning
// the scope catalog so the client editor can offer the grantable scopes.
func GetOAuthServerScopes(c *gin.Context) {
	common.ApiSuccess(c, oauthserver.SupportedScopes())
}

// ListMyOAuthAuthorizations backs GET /api/oauth-server/authorizations
// (UserAuth), listing the applications the signed-in user has connected, with
// the granted scopes rendered for display. A grant whose client has since been
// deleted is skipped.
func ListMyOAuthAuthorizations(c *gin.Context) {
	grants, err := model.ListOAuthUserGrants(c.GetInt("id"))
	if err != nil {
		common.ApiError(c, err)
		return
	}
	out := make([]gin.H, 0, len(grants))
	for _, grant := range grants {
		client, err := model.GetOAuthClientByClientId(grant.ClientId)
		if err != nil {
			continue
		}
		scopeNames := grant.GetScopes()
		scopeDetails := make([]gin.H, 0, len(scopeNames))
		for _, name := range scopeNames {
			if scope, ok := oauthserver.LookupScope(name); ok {
				scopeDetails = append(scopeDetails, gin.H{
					"name":        scope.Name,
					"title":       scope.Title,
					"description": scope.Description,
				})
			}
		}
		out = append(out, gin.H{
			"client_id": grant.ClientId,
			"client": gin.H{
				"name":        client.Name,
				"description": client.Description,
				"logo":        client.Logo,
				"homepage":    client.Homepage,
			},
			"scopes":        scopeNames,
			"scope_details": scopeDetails,
			"created_at":    grant.CreatedAt,
			"updated_at":    grant.UpdatedAt,
		})
	}
	common.ApiSuccess(c, out)
}

// DeleteMyOAuthAuthorization backs DELETE /api/oauth-server/authorizations/:client_id
// (UserAuth), disconnecting an application: the consent is removed and every
// token issued to that client for this user is revoked.
func DeleteMyOAuthAuthorization(c *gin.Context) {
	clientId := strings.TrimSpace(c.Param("client_id"))
	if clientId == "" {
		common.ApiErrorMsg(c, "invalid client id")
		return
	}
	if err := model.DeleteOAuthUserGrant(c.GetInt("id"), clientId); err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, nil)
}
