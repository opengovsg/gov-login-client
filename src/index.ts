import {
  Client,
  ClientAuthMethod,
  generators,
  Issuer,
  ResponseType,
} from 'openid-client'

const GOV_LOGIN_SIGNING_ALG = 'RS256'
const GOV_LOGIN_SUPPORTED_FLOWS: ResponseType[] = ['code']
const GOV_LOGIN_AUTH_METHOD: ClientAuthMethod = 'client_secret_post'

type GovLoginClientOptions = {
  clientId: string
  clientSecret: string
  redirectUri?: string
  hostname: string
  apiVersion?: number
}

export class GovLoginClient {
  private client: Client

  constructor({
    clientId,
    clientSecret,
    redirectUri,
    // TODO: update the default hostname to the GovLogin domain and make optional
    hostname,
    apiVersion = 1,
  }: GovLoginClientOptions) {
    // TODO: Discover GovLogin issuer metadata via .well-known endpoint
    const { Client } = new Issuer({
      issuer: new URL(hostname).origin,
      authorization_endpoint: `${hostname}/api/v${apiVersion}/oidc/auth`,
      token_endpoint: `${hostname}/api/v${apiVersion}/oidc/token`,
      userinfo_endpoint: `${hostname}/api/v${apiVersion}/oidc/userinfo`,
      jwks_uri: `${hostname}/api/v${apiVersion}/oidc/jwks`,
    })

    this.client = new Client({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: redirectUri ? [redirectUri] : undefined,
      id_token_signed_response_alg: GOV_LOGIN_SIGNING_ALG,
      response_types: GOV_LOGIN_SUPPORTED_FLOWS,
      token_endpoint_auth_method: GOV_LOGIN_AUTH_METHOD,
    })
  }

  /**
   * Generates authorization url for gov-login OIDC flow
   * @param state A random string to prevent CSRF
   * @param scopes Array or space-separated scopes, must include openid
   * @param nonce Specify null if no nonce
   * @param redirectUri The redirect URI used in the authorization request, defaults to the one registered with the client
   * @returns
   */
  authorizationUrl(
    state: string,
    scope: string | string[] = 'openid',
    nonce: string | null = generators.nonce(),
    redirectUri: string = this.getFirstRedirectUri(),
  ): { url: string; nonce?: string } {
    const url = this.client.authorizationUrl({
      scope: typeof scope === 'string' ? scope : scope.join(' '),
      nonce: nonce ?? undefined,
      state,
      redirect_uri: redirectUri,
    })
    const result: { url: string; nonce?: string } = { url }
    if (nonce) {
      result.nonce = nonce
    }
    return result
  }

  private getFirstRedirectUri(): string {
    if (
      !this.client.metadata.redirect_uris ||
      this.client.metadata.redirect_uris.length === 0
    ) {
      // eslint-disable-next-line typesafe/no-throw-sync-func
      throw new Error('No redirect URI registered with this client')
    }
    return this.client.metadata.redirect_uris[0]
  }

  /**
   * Callback handler for gov-login OIDC flow
   * @param code The authorization code received from the authorization server
   * @param nonce Specify null if no nonce
   * @param redirectUri The redirect URI used in the authorization request, defaults to the one registered with the client
   * @returns The sub of the user and access token
   */
  async callback(
    code: string,
    nonce: string | null = null,
    redirectUri = this.getFirstRedirectUri(),
  ): Promise<{ sub: string; accessToken: string }> {
    const tokenSet = await this.client.callback(
      redirectUri,
      { code },
      { nonce: nonce ?? undefined },
    )
    const { sub } = tokenSet.claims()
    const { access_token: accessToken } = tokenSet
    if (!sub || !accessToken) {
      throw new Error('Missing sub claim or access token')
    }
    return { sub, accessToken }
  }

  /**
   * Retrieve verified user info
   * @param accessToken The access token returned in the callback function
   * @returns The sub of the user - note that gov-login will only return the sub for now
   */
  async userinfo(accessToken: string): Promise<{ sub: string }> {
    /**
     * sub: user sub (also returned previously in id_token)
     */
    const { sub } = await this.client.userinfo<{
      sub: string | undefined
      data: Record<string, string> | undefined
    }>(accessToken)
    return { sub }
  }
}

export default GovLoginClient
