import HttpClient from "../httpClient.js";
import { TokenResponse, UserProfile } from "../types.js";

interface LoginPayload {
  username: string;
  password: string;
}

interface TokenResponsePayload {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  access_token_expires_in: number;
  refresh_token_expires_in?: number;
  csrf_token: string;
}

interface UserResponsePayload {
  user_id: string;
  username: string;
  email: string | null;
  is_admin: boolean;
  scopes: string[];
  org_id: string | null;
}

export class AuthClient {
  constructor(private readonly http: HttpClient) {}

  async login(payload: LoginPayload): Promise<TokenResponse> {
    const body: Record<string, unknown> = {
      username: payload.username,
      password: payload.password,
    };

    const response = await this.http.post<TokenResponsePayload>("/api/v1/auth/token", {
      body,
    });

    return mapTokenResponse(response);
  }

  async currentUser(): Promise<UserProfile> {
    const response = await this.http.get<UserResponsePayload>("/api/v1/auth/me");
    return mapUserProfile(response);
  }
}

function mapTokenResponse(payload: TokenResponsePayload): TokenResponse {
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    tokenType: payload.token_type,
    accessTokenExpiresIn: payload.access_token_expires_in,
    refreshTokenExpiresIn: payload.refresh_token_expires_in,
    csrfToken: payload.csrf_token,
  };
}

function mapUserProfile(payload: UserResponsePayload): UserProfile {
  return {
    userId: payload.user_id,
    username: payload.username,
    email: payload.email,
    isAdmin: payload.is_admin,
    orgId: payload.org_id,
    scopes: payload.scopes ?? [],
  };
}

export default AuthClient;
