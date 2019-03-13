package service

import (
	"strings"
	"time"

	"gopkg.in/jcmturner/gokrb5.v7/credentials"
	"gopkg.in/jcmturner/gokrb5.v7/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v7/messages"
	"gopkg.in/jcmturner/rpc.v1/mstypes"
)

// VerifyAPREQ verifies an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func VerifyAPREQ(APReq messages.APReq, s *Settings) (bool, *credentials.Credentials, error) {
	var creds *credentials.Credentials

	ok, err := APReq.Verify(s.Keytab, s.MaxClockSkew(), s.ClientAddress())
	if err != nil || !ok {
		return false, creds, err
	}

	if s.RequireHostAddr() && len(APReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}

	// Check for replay
	rc := GetReplayCache(s.MaxClockSkew())
	if rc.IsReplay(APReq.Ticket.SName, APReq.Authenticator) {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewFromPrincipalName(APReq.Authenticator.CName, APReq.Authenticator.CRealm)
	creds = c
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)

	//PAC decoding
	err = addPACAttributes(APReq.Ticket, creds, s)
	if err != nil {
		return false, creds, err
	}
	return true, creds, nil
}

func addPACAttributes(tkt messages.Ticket, creds *credentials.Credentials, s *Settings) error {
	if !s.disablePACDecoding {
		isPAC, pac, err := tkt.GetPACType(s.Keytab, s.KeytabPrincipal(), s.Logger())
		if isPAC && err != nil {
			return err
		}
		if isPAC {
			// There is a valid PAC. Adding attributes to creds
			creds.SetADCredentials(credentials.ADCredentials{
				GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
				LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
				LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
				PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
				EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
				FullName:            pac.KerbValidationInfo.FullName.Value,
				UserID:              int(pac.KerbValidationInfo.UserID),
				PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
				LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
				LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
				LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.String(),
			})
			if pac.ClientClaimsInfo.ClaimsSetMetadata.CompressionFormat == mstypes.CompressionFormatNone {
				//Only uncompressed supported currently by gokrb5
				for _, c := range pac.ClientClaimsInfo.ClaimsSet.ClaimsArrays {
					for _, e := range c.ClaimEntries {
						id := strings.Split(e.ID, "/")
						attr := strings.Split(id[len(id)-1], ":")[0]
						switch e.Type {
						case mstypes.ClaimTypeIDString:
							creds.SetAttribute(attr, e.TypeString.Value)
						case mstypes.ClaimTypeIDInt64:
							creds.SetAttribute(attr, e.TypeInt64.Value)
						case mstypes.ClaimTypeIDUInt64:
							creds.SetAttribute(attr, e.TypeUInt64.Value)
						case mstypes.ClaimsTypeIDBoolean:
							creds.SetAttribute(attr, e.TypeBool.Value)
						}
					}
				}
			}
		}
	}
	return nil
}
