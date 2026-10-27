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

package router

import (
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/pkg/oauthscope"
	"github.com/QuantumNous/new-api/service/oauthserver"

	"github.com/gin-gonic/gin"
)

// SetOAuthServerRouter registers new-api's public OAuth 2.0 / OpenID Connect
// authorization-server endpoints. They speak the OAuth wire format (not the
// dashboard JSON envelope) and are reached without a dashboard session, so the
// group carries its own CORS and rate limiting rather than inheriting the /api
// chain. Credential-sensitive endpoints (authorize, token, revoke) are rate
// limited; discovery, JWKS, and userinfo are not (the first two are
// cacheable and userinfo already requires a valid bearer token).
func SetOAuthServerRouter(router *gin.Engine) {
	oauthRouter := router.Group("")
	oauthRouter.Use(middleware.CORS())
	oauthRouter.Use(middleware.RouteTag("oauth-server"))
	{
		oauthRouter.GET("/.well-known/openid-configuration", controller.OAuthDiscovery)
		oauthRouter.GET("/oauth2/jwks", controller.OAuthJWKS)
		oauthRouter.GET("/oauth2/authorize", middleware.CriticalRateLimit(), controller.OAuthAuthorize)
		oauthRouter.POST("/oauth2/token", middleware.CriticalRateLimit(), controller.OAuthToken)
		oauthRouter.GET("/oauth2/userinfo", controller.OAuthUserInfo)
		oauthRouter.POST("/oauth2/userinfo", controller.OAuthUserInfo)
		oauthRouter.POST("/oauth2/revoke", middleware.CriticalRateLimit(), controller.OAuthRevoke)
	}

	setOAuthScopedAPIRouter(router)
}

// setOAuthScopedAPIRouter mounts the OAuth-scoped business API under /oauth2/api.
// Unlike the /api dashboard group (session/PAT auth via middleware.UserAuth), each
// sub-group here is guarded by oauthscope.DashboardScopeAuth(<scope>): it resolves
// the bearer access token to its resource owner, enforces the required scope (and,
// for sensitive scopes, that the issuing client is admin-marked Trusted), and
// writes the same request-context keys a dashboard session would. The existing
// dashboard handlers therefore run unchanged as the token's owner — every one of
// them scopes its work to c.GetInt("id"), so a token only ever reaches its own
// account. The access token authorizes these endpoints directly, replacing the
// removed POST /oauth2/keys relay-key bridge. Identity claims stay on
// /oauth2/userinfo (registered above); this group covers the wallet, API-key and
// model-catalog domains.
func setOAuthScopedAPIRouter(router *gin.Engine) {
	api := router.Group("/oauth2/api")
	api.Use(middleware.CORS())
	api.Use(middleware.RouteTag("oauth-server-api"))

	// wallet.read — the owner's balance and the configured top-up options.
	walletRead := api.Group("/wallet")
	walletRead.Use(oauthscope.DashboardScopeAuth(oauthserver.ScopeWalletRead))
	{
		walletRead.GET("", controller.OAuthWalletBalance)
		walletRead.GET("/topup-options", controller.GetTopUpInfo)
	}

	// wallet.topup (sensitive) — create top-up orders / payment links and redeem
	// gift codes on the owner's behalf. CriticalRateLimit mirrors the dashboard
	// mounts of these money-moving handlers.
	walletTopUp := api.Group("/wallet")
	walletTopUp.Use(oauthscope.DashboardScopeAuth(oauthserver.ScopeWalletTopUp))
	{
		walletTopUp.POST("/topup", middleware.CriticalRateLimit(), controller.RequestEpay)
		walletTopUp.POST("/redeem", middleware.CriticalRateLimit(), controller.TopUp)
	}

	// apikeys.manage (sensitive) — full CRUD over the owner's relay API keys.
	// TokenOperationAudit records the same security-audit entries as the dashboard
	// token group (its switch recognizes these /oauth2/api/tokens paths).
	tokens := api.Group("/tokens")
	tokens.Use(oauthscope.DashboardScopeAuth(oauthserver.ScopeAPIKeysManage))
	tokens.Use(middleware.TokenOperationAudit())
	{
		tokens.GET("", controller.GetAllTokens)
		tokens.GET("/search", middleware.SearchRateLimit(), controller.SearchTokens)
		tokens.GET("/auto-groups", controller.GetTokenAutoGroups)
		tokens.GET("/:id", controller.GetToken)
		tokens.POST("/:id/key", middleware.CriticalRateLimit(), middleware.DisableCache(), controller.GetTokenKey)
		tokens.POST("", controller.AddToken)
		tokens.PUT("", controller.UpdateToken)
		tokens.DELETE("/:id", controller.DeleteToken)
		tokens.POST("/batch", controller.DeleteTokenBatch)
		tokens.POST("/batch/keys", middleware.CriticalRateLimit(), middleware.DisableCache(), controller.GetTokenKeysBatch)
	}

	// models.read — the groups, models and pricing available to the owner. This
	// group has no :id path parameter, so GetUserModels (which prefers c.Param("id")
	// when present) resolves to the token owner from context. DashboardListModels is
	// intentionally excluded: it returns the deployment-wide channel/model topology,
	// which exceeds a per-owner read scope.
	modelsRead := api.Group("")
	modelsRead.Use(oauthscope.DashboardScopeAuth(oauthserver.ScopeModelsRead))
	{
		modelsRead.GET("/models", controller.GetUserModels)
		modelsRead.GET("/groups", controller.GetUserGroups)
		modelsRead.GET("/pricing", controller.GetPricing)
	}
}
