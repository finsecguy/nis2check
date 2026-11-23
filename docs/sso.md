## Single sign-on

### Microsoft Entra ID

1. In the Entra admin centre, open **App registrations > New registration**.
2. Name it "NIS2 Gap Assessment", choose **Accounts in this organizational directory only**, and add a **Web** redirect URI: `https://nis2.yourcompany.com/sso/entra/callback`.
3. Under **Certificates & secrets**, create a client secret.
4. Under **Token configuration > Add optional claim > ID**, add the `xms_edov` claim. Entra does not verify the `email` claim by default, so without `xms_edov` the app cannot confirm an address belongs to the person signing in, and will refuse to link it to an admin-created account (see "Who can sign in" below).
5. In `.env`, set `NIS2_ENTRA_TENANT_ID`, `NIS2_ENTRA_CLIENT_ID` and `NIS2_ENTRA_CLIENT_SECRET`, then restart.

### Google Workspace

1. In Google Cloud Console, open **APIs & Services > Credentials > Create credentials > OAuth client ID** (type: Web application).
2. Add the redirect URI `https://nis2.yourcompany.com/sso/google/callback`.
3. In `.env`, set `NIS2_GOOGLE_CLIENT_ID` and `NIS2_GOOGLE_CLIENT_SECRET`, then restart.

### Who can sign in

By default, only people an administrator has added under **Users** can sign in with SSO; their account is linked to their SSO identity at first sign-in, provided the identity provider has verified the email address. Google always does this; for Entra ID, add the `xms_edov` optional ID-token claim (see step 4 above), or first sign-ins cannot be linked to the pre-created account. To let everyone in your company in automatically, set `NIS2_SSO_ALLOWED_DOMAINS=yourcompany.com` and `NIS2_SSO_AUTO_PROVISION=true`; new accounts get the viewer role (or `NIS2_SSO_DEFAULT_ROLE=assessor`) and never the administrator role. Once SSO works, you can turn off password sign-in with `NIS2_LOCAL_LOGIN=false`.
