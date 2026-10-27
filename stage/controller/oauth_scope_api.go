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
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"github.com/gin-gonic/gin"
)

// OAuthWalletBalance answers the wallet.read half that reports the owner's
// balance, for the OAuth-scoped API group (GET /oauth2/api/wallet). It is a
// deliberately slim alternative to GetSelf: the wallet.read scope grants a look
// at the quota balance only, so this returns just the remaining and used quota
// and never the identity, affiliate, payment-customer or setting fields GetSelf
// exposes. The top-up options half of wallet.read is served by GetTopUpInfo.
//
// The owner is taken from the request context (set by DashboardScopeAuth from the
// access token), never from a request parameter, so there is no cross-user path.
func OAuthWalletBalance(c *gin.Context) {
	userId := c.GetInt("id")
	remainQuota, err := model.GetUserQuota(userId, false)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	usedQuota, err := model.GetUserUsedQuota(userId)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{
		"quota":      remainQuota,
		"used_quota": usedQuota,
	})
}
